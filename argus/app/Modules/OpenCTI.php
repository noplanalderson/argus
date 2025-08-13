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
        return [
            "query" => "query StixCyberObservablesLinesPaginationQuery(\$types: [String], \$search: String, \$count: Int!, \$cursor: ID, \$orderBy: StixCyberObservablesOrdering, \$orderMode: OrderingMode, \$filters: FilterGroup) {\n  ...StixCyberObservablesLines_data_4GmerJ\n}\n\nfragment StixCyberObservableLine_node on StixCyberObservable {\n  __isStixCyberObservable: __typename\n  id\n  entity_type\n  parent_types\n  observable_value\n  created_at\n  draftVersion {\n    draft_id\n    draft_operation\n  }\n  createdBy {\n    __typename\n    __isIdentity: __typename\n    id\n    name\n    entity_type\n  }\n  ... on IPv4Addr {\n    countries {\n      edges {\n        node {\n          name\n          x_opencti_aliases\n          id\n        }\n      }\n    }\n  }\n  ... on IPv6Addr {\n    countries {\n      edges {\n        node {\n          name\n          x_opencti_aliases\n          id\n        }\n      }\n    }\n  }\n  objectMarking {\n    id\n    definition\n    x_opencti_order\n    x_opencti_color\n  }\n  objectLabel {\n    id\n    value\n    color\n  }\n  creators {\n    id\n    name\n  }\n}\n\nfragment StixCyberObservablesLines_data_4GmerJ on Query {\n  stixCyberObservables(\n    types: \$types\n    search: \$search\n    first: \$count\n    after: \$cursor\n    orderBy: \$orderBy\n    orderMode: \$orderMode\n    filters: \$filters\n  ) {\n    edges {\n      node {\n        __typename\n        id\n        standard_id\n        entity_type\n        observable_value\n        created_at\n        x_opencti_score\n        x_opencti_description\n        objectMarking {\n          id\n          definition\n          x_opencti_order\n          x_opencti_color\n        }\n        ...StixCyberObservableLine_node\n      }\n      cursor\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n      globalCount\n    }\n  }\n}",
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
        $res = $this->client->request($method, $_ENV['OPENCTI_URL'] . $endpoint,  $params);
        if ($res->getStatusCode() == 200) {
            $data = json_decode($res->getBody()->getContents(), true);
            return ['status' => true, 'code' => $res->getStatusCode(), 'data' => $data];
        } 
        return ['status' => false, 'code' => $res->getStatusCode(), 'data' => []];
    }

    private function _getObservable()
    {
        $params = [
            'headers' => $this->headers,
            'body' => json_encode($this->buildRequest())
        ];
        $res = $this->request('POST', '/graphql', $params);
        if(!$res['status']) {
            return ['status' => false, 'code' => $res['code'], 'message' => 'Failed to get observable data', 'data' => []];
        } else {
            return ['status' => true, 'code' => $res['code'], 'message' => 'Ok', 'data' => $res['data']];
        }
    }

    private function __scoring()
    {
        $opencti = $this->_getObservable();
        $this->status = $opencti['status'];
        if($this->status === true) {
            $this->data = $opencti['data'];
            $data = $this->data['data']['stixCyberObservables']['edges'][0]['node'];
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

    private function _saveResults()
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

        $this->_saveResults();

        return [
            'status' => $this->status,
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