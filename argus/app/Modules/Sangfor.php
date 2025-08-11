<?php
namespace app\Modules;

class Sangfor 
{
    protected $client;
    protected $headers;
    protected $token = '';
    public function __construct()
    {
        $this->client = initGuzzle([
            'verify' => false // Disable SSL certificate verification
        ]);

        $this->headers = ['Content-Type' => 'application/json'];
    }

    private function request($method, $endpoint, $params)
    {
        $res = $this->client->request($method, $_ENV['FW_HOST'] . $endpoint,  $params);
        if ($res->getStatusCode() == 200) {
            $data = json_decode($res->getBody()->getCOntents(), true);
            return $data;
        }

        return false;
    }

    public function login()
    {
        $body = json_encode([
            'name' => $_ENV['FW_USER'],
            'password' => $_ENV['FW_PASS']
        ]);

        $params = [
            'headers' => $this->headers,
            'body' => $body,
        ];

        $result = $this->request('POST', 'api/v1/namespaces/public/login', $params);
        if($result !== false) {
            $this->token = $result['data']['loginResult']['token'];
        }
        return $result;
    }

    public function keepalive()
    {
        $headers = array_merge($this->headers, ['Cookie' => "token={$this->token}"]);
        $res = $this->request('GET', 'api/v1/namespaces/public/keepalive', $headers);

        if ($res['code'] == 1003) {
            $this->login();
        }
    }

    public function getBlacklist(int $page){
        $headers = array_merge($this->headers, ['Cookie' => "token={$this->token}"]);
        $res = $this->request('GET', "api/v1/namespaces/public/whiteblacklist?type=BLACK&_length=10&_start={$page}",  ['headers' => $headers]);
        
        if(!$res) {
            $this->login();
            echo "<script>location.reload()</script>";
            exit;
        }
        
        return $res;
    }

    public function getWhitelist(int $page){
        $headers = array_merge($this->headers, ['Cookie' => "token={$this->token}"]);
        $res = $this->request('GET',"api/v1/namespaces/public/whiteblacklist?type=WHITE&_length=10&_start={$page}",  ['headers' => $headers]);
        
        if(!$res) {
            $this->login();
            echo "<script>location.reload()</script>";
            exit;
        }
        
        return $res;
    }

    public function createblackwhite($data) 
    {
        $headers = [
            'Content-Type' => 'application/json',
            'Cookie' => "token={$this->token}"
        ];

        $body = json_encode([
            'enable' => $data['enable'],
            'type' => $data['type'],
            'url' => $data['ip_address'],
            'description' => $data['description']
        ]);

        $res = $this->request('POST', 'api/v1/namespaces/public/whiteblacklist', [
            'headers' => $headers,
            'body' => $body
        ]);

        return $res;
    }

    public function tempblock($data)
    {
        $headers = [
            'Content-Type' => 'application/json',
            'Cookie' => "token={$this->token}"
        ];

        $body = json_encode([
            'ipType' => 'SRC',
            'srcIP' => [ $data['ip_address'] ],
            'blockTime' => $data['blockmode']
        ]);

        $res = $this->request('POST', 'api/batch/v1/namespaces/public/blockip',  [
            'headers' => $headers,
            'body' => $body
        ]);
        
        return $res;
    }

    public function deletelackwhite($data)
    {
        $headers = [
            'Content-Type' => 'application/json',
            'Cookie' => "token={$this->token}"
        ];

        $body = json_encode([
            'enable' => $data['enable'],
            'type' => $data['type'],
            'url' => $data['url'],
            'description' => $data['description']
        ]);

        $res = $this->request('DELETE', "api/v1/namespaces/public/whiteblacklist/{$data['url']}",  [
            'headers' => $headers,
            'body'=>$body,
        ]);
        
        return $res;
    }
}