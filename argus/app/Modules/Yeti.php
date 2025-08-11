<?php
namespace app\Modules;

class Yeti 
{
    protected $client;
    protected $headers;
    protected $token = '';
    protected $observableId = '';
    public function __construct()
    {
        $this->client = initGuzzle([
            'verify' => false // Disable SSL certificate verification
        ]);

        $this->headers = ['Content-Type' => 'application/json'];
    }

    private function request($method, $endpoint, $params)
    {
        $res = $this->client->request($method, $_ENV['YETI_URL'] . $endpoint,  $params);
        if ($res->getStatusCode() == 200) {
            $data = json_decode($res->getBody()->getContents(), true);
            return ['status' => true, 'code' => $res->getStatusCode(), 'data' => $data];
        } 
        return ['status' => false, 'code' => $res->getStatusCode(), 'data' => []];

    }

    public function getAccessToken()
    {
        $params = [
            'headers' => array_merge($this->headers, ['x-yeti-apikey' => $_ENV['YETI_API_KEY']]),
        ];
        $data = $this->request('POST', '/api/v2/auth/api-token', $params);
        if ($data['status']) {
            $this->token = $data['data']['access_token'];
        }
    }

    public function getObservable($observable)
    {
        //{"observables":["52.167.144.140"],"add_unknown":false,"add_tags":[],"add_type":"guess","regex_match":false}
        $body = array(
            "observables" => [$observable],
            "add_unknown" => false,
            "add_tags" => [],
            "add_type" => "guess",
            "regex_match" => false
        );
        $params = [
            'headers' => array_merge($this->headers, ['Authorization' => "Bearer {$this->token}"]),
            'body' => json_encode($body)
        ];
        $res = $this->request('POST', '/api/v2/graph/match', $params);
        if(!$res['status']) {
            return ['status' => false, 'code' => $res['code'], 'message' => 'Failed to get observable data', 'data' => []];
        } else {
            return ['status' => true, 'code' => $res['code'], 'message' => 'Ok', 'data' => $res['data']];
        }
    }

    public function addObservable($observable)
    {
        $tags = [];
        $context = [];
        $params = [
            'headers' => array_merge($this->headers, ['Authorization' => "Bearer {$this->token}"]),
            'body' => json_encode([
                'observable' => [
                    'type' => 'ipv4',
                    'value' => $observable,
                ]
            ])
        ];

        $res = $this->request('POST', '/api/v2/observables/extended', $params);
        
        if(!$res['status']) {
            return ['status' => false, 'code' => $res['code'], 'message' => 'Failed to add observable', 'data' => []];
        } else {
            if(!empty($res['data']['id'])) {
                $this->observableId = $res['data']['id'];
                $tags = $this->addObservableTags();
            }
            return [
                'status' => true, 
                'code' => $res['code'], 
                'message' => 'Observable added successfully',
                'data' => [
                    'observable' => $res['data'], 
                    'tags' => $tags['data']['tags'] ?? [], 
                    'context' => $context['data']['context'] ?? []
                ]
            ];
        }

    }

    public function addObservableTags()
    {
        $params = [
            'headers' => array_merge($this->headers, ['Authorization' => "Bearer {$this->token}"]),
            'body' => json_encode([
                'ids' => [$this->observableId],
                'strict' => true,
                'tags' => ['wazuh', 'web_attack', 'accesslog']
            ])
        ];

        $res = $this->request('POST', '/api/v2/observables/tag', $params);
        
        if(!$res['status']) {
            return ['status' => false, 'code' => $res['code'], 'message' => 'Failed to add observable tags', 'data' => []];
        } else {
            $context = $this->addContext();
            return ['status' => true, 'code' => $res['code'], 'data' => ['tags' => $res['data'], 'context' => $context['data']]];
        }
    }

    public function addContext()
    {
        $params = [
            'headers' => array_merge($this->headers, ['Authorization' => "Bearer {$this->token}"]),
            'body' => json_encode([
                'context' => [
                    ['source' => 'WazuhSIEM'],
                    ['source' => 'TangerangKota-CSIRT']
                ]
            ])
        ];

        $res = $this->request('PUT', "/api/v2/observables/{$this->observableId}/context", $params);
        if(!$res['status']) {
            return ['status' => false, 'code' => $res['code'], 'message' => 'Failed to add observable context', 'data' => []];
        } else {
            return ['status' => true, 'code' => $res['code'], 'data' => $res['data']['context']];
        }
    }
}