<?php
namespace App\Libraries;

use GuzzleHttp\Client;
use GuzzleHttp\Promise\EachPromise;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ConnectException;
use Ramsey\Uuid\Uuid;
use App\Cores\DB;

class ArgusAggregator
{
    protected $client;
    protected $observable;
    protected $results = [];
    protected $sources = [];
    protected $requests = [];
    protected $promises = [];
    protected string $logFile;
    
    public function __construct(string $observable, array $sources = [])
    {
        $this->client = new Client([
            'verify'  => false,
            'timeout' => 10
        ]);
        
        $this->logFile = ROOTPATH . 'logs/argus_tip.log';

        $this->observable = trim($observable);

        $this->sources = $sources;
    }

    private function logError(string $source, string $error): void
    {
        $message = sprintf(
            "[%s] [%s] %s%s",
            date('Y-m-d H:i:s'),
            $source,
            preg_replace('/\n/', '', $error),
            PHP_EOL
        );

        file_put_contents($this->logFile, $message, FILE_APPEND);
    }

    private function buildRequests(): void
    {
        foreach ($this->sources as $source => $info) {
            $method  = $info['method'];
            $url     = is_callable($info['url']) ? $info['url']($this->observable) : $info['url'];
            $headers = $info['headers'] ?? [];
            $body    = isset($info['body']) && is_callable($info['body']) ? $info['body']($this->observable) : null;
            $multipart = isset($info['multipart']) && is_callable($info['multipart']) ? $info['multipart']($this->observable) : null;

            $options = ['headers' => $headers];
            if ($method === 'POST' && $body !== null) {
                $options['body'] = $body;
            } elseif ($method === 'POST' && $multipart !== null) {
                $options['multipart'] = $multipart;
            }

            $this->requests[] = $source;
            $this->promises[] = $this->client->requestAsync($method, $url, $options);
        }
    }

    private function save($results)
    {
        try {
            DB::beginTransaction();
            $job_id = Uuid::uuid7()->toString();
            DB::table('tb_jobs')->where('observable', $this->observable)->delete();
            DB::table('tb_jobs')->insert([
                'job_id' => $job_id,
                'observable' => $this->observable,
                'results'    => json_encode($results),
                'created_at' => date('Y-m-d H:i:s')
            ]);
            DB::commit();
        } catch (\Throwable $th) {
            DB::rollback();
            $this->logError('[DB_OPERATION]', $th->getMessage());
        }
    }

    public function run(): array
    {
        $results = DB::table('tb_jobs')->select('*')->where('observable', $this->observable)->orderBy('created_at', 'desc')->first();

        if ($results && isset($results['created_at'])) {
            $createdAt = strtotime($results['created_at']);
            $reanalyze = $_ENV['FORCE_REANALYZE'] ?? 60;
            if ($createdAt !== false && $createdAt >= strtotime("-{$reanalyze} days")) {
                return array_merge(['observable' => $this->observable], json_decode($results['results'], true));
            }
        }

        $this->buildRequests();

        $results = [];

        $eachPromise = new EachPromise($this->promises, [
            'concurrency' => $_ENV['ARGUS_CONCURRENCY'] ?? 3,
            'fulfilled' => function ($response, $index) use (&$results) {
                $source = $this->requests[$index] ?? 'unknown';
                $results[$source] = [
                    'success' => true,
                    'results' => json_decode($response->getBody(), true)
                ];
            },
            'rejected' => function ($reason, $index) use (&$results) {
                $source = $this->requests[$index] ?? 'unknown';

                if ($reason instanceof ConnectException) {
                    $error = 'Connection error: ' . $reason->getMessage();
                } elseif ($reason instanceof RequestException) {
                    $status = $reason->hasResponse() 
                        ? $reason->getResponse()->getStatusCode() 
                        : 'no response';
                    $error = "Request error [status {$status}]: " . $reason->getMessage();
                } elseif ($reason instanceof \Throwable) {
                    $error = 'Unexpected error: ' . $reason->getMessage();
                } else {
                    $error = 'Unknown error type';
                }

                $results[$source] = [
                    'success' => false,
                    'error'   => $error
                ];

                $this->logError($source, $error);
            },
        ]);

        $eachPromise->promise()->wait();
        $this->save($results);

        return array_merge(['observable' => $this->observable], $results);
    }
}
