<?php
namespace App\Modules;
use App\Config\Database;
use Ramsey\Uuid\Uuid;
/**
 * OpenCTI Integration Module
 */
class OpenCTI
{
    protected $client;

    protected $headers;

    protected $status = false;

    protected $data = [];

    protected $observable = '';

    protected $decision = ['notification' => true, 'reporting' => true];

    protected $dataMapping = [
        'id' => null,
        'opencti_score' => 0,
        'opencti_description' => '',
        'classification' => []
    ];

    public function __construct($observable)
    {
        $this->client = initGuzzle([
            'verify' => false // Disable SSL certificate verification
        ]);

        $this->observable = $observable;

        $this->headers = [
            'Content-Type' => 'application/json',
            'Authorization' => "Bearer {$_ENV['OPENCTI_API_KEY']}"
        ];
    }

    private function buildRequest()
    {
        $path = ROOTPATH . '/script/query.graphql';
        if (!file_exists($path)) {
            throw new \RuntimeException("Query file not found: " . $path);
        }
        $query = trim(file_get_contents($path));

        return [
            "query" => $query,
            "variables" => [
                "count" => 1,
                "search" => $this->observable,
                "orderMode" => "desc",
                "orderBy" => "_score",
                "filters" => [
                    "mode" => "and",
                    "filters" => [
                        [
                            "key" => "entity_type",
                            "values" => [],
                            "operator" => "eq",
                            "mode" => "or"
                        ]
                    ],
                    "filterGroups" => []
                ]
            ],
            "operationName" => "StixCyberObservablesLinesPaginationQuery"
        ];
    }

    private function request($method, $endpoint, $params)
    {
        try {
            $res = $this->client->request($method, $_ENV['OPENCTI_URL'] . $endpoint,  $params);
            $code = $res->getStatusCode();
            if ($code == 200) {
                $data = json_decode($res->getBody()->getContents(), true);
                return ['status' => true, 'code' => $code, 'data' => $data];
            }
        } catch (\Exception $e) {
            $code = $e->getCode();
        }
        return ['status' => false, 'code' => $code, 'data' => []];
    }

    private function _getObservable()
    {
        $params = [
            'headers' => $this->headers,
            'body' => json_encode($this->buildRequest())
        ];
        return $this->request('POST', '/graphql', $params);
    }

    private function __scoring()
    {
        $opencti = $this->_getObservable();
        $this->status = $opencti['status'];
        if($this->status === true) {
            $this->data = $opencti['data'];
            $data = $this->data['data']['stixCyberObservables']['edges'][0]['node'] ?? [];
            if(!empty($data)) {
                foreach ($data['objectLabel'] as $value) {
                    $this->dataMapping['classification'][$data['createdBy']['name']][] = $value['value'];
                }
                $this->dataMapping['opencti_score'] = $data['x_opencti_score'] ?? 0;
                $this->dataMapping['id'] = $data['id'];
                $this->dataMapping['opencti_description'] = $data['x_opencti_description'] ?? $this->observable;
            }
        }

    }

    private function __saveResults()
    {
        $db = (new Database())->getConnection();

        $uuid   = Uuid::uuid7()->toString();

        $stmt = $db->prepare("INSERT INTO `tb_file_hash` (
                    `hash_id`, `file_hash`, `observable_name`, `classification`, `malprobe_score`,
                    `vt_score`, `mb_score`, `yara_score`, `opencti_score`, `overall_score`, `decision`) VALUES
                    (:hash_id, :file_hash, :observable_name, :classification, :malprobe_score,
                    :vt_score, :mb_score, :yara_score, :opencti_score, :overall_score, :decision)");
        $stmt->execute([
            ':hash_id' => $uuid,
            ':file_hash' => $this->observable,
            ':observable_name' => $this->observable,
            ':classification' => json_encode($this->dataMapping['classification']),
            ':malprobe_score' => null,
            ':vt_score' => null,
            ':mb_score' => null,
            ':yara_score' => null,
            ':opencti_score' => $this->dataMapping['opencti_score'],
            ':overall_score' => $this->dataMapping['opencti_score'],
            ':decision' => json_encode($this->decision)
        ]);
    }

    public function run()
    {
        $this->__scoring();
        $this->__saveResults();

        return [
            'status' => $this->status,
            'type' => 'hash',
            'opencti' => $this->data,
            'scores' => $this->dataMapping['opencti_score'],
            'hash' => $this->observable,
            'description' => "Hash analysis based on OpenCTI (Scores {$this->dataMapping['opencti_score']})",
            'reference' => "{$_ENV['OPENCTI_URL']}/dashboard/observations/observables/{$this->dataMapping['id']}",
            'data' => array_merge(
                $this->dataMapping,
                ['decision' => $this->decision]
            )
        ];
    }
}