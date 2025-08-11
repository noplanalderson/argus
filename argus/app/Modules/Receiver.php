<?php
namespace App\Modules;

class Receiver
{
    protected $auth;

    protected $headers;

    protected $jobId;

    public function __construct($jobId)
    {
        $this->jobId = $jobId;

        $this->headers = [
            'Authorization' => 'Token '.$_ENV['INTELOWL_API_KEY'],
            'Accept' => 'application/json',
        ];
    }

    public function exec()
    {
        $client = new \GuzzleHttp\Client();
        try {
            $response = $client->request('GET', $_ENV['INTELOWL_URL'] . "/api/jobs/{$this->jobId}", [
                'headers' => $this->headers
            ]);

            $body = $response->getBody();
            if($response->getStatusCode() == 200) {
                $data = [
                    'status' => true,
                    'code' => $response->getStatusCode(),
                    'message' => 'OK',
                    'data' => json_decode($body, true)
                ];
            } else {
                $data = [
                    'status' => false,
                    'code' => $response->getStatusCode(),
                    'message' => 'Failed to fetch data.'
                ];
            }
        } catch (\Exception $e) {
            $data = [
                'status' => false,
                'code' => $e->getCode(),
                'message' => $e->getMessage()
            ];
        }

        return $data;
    }
}