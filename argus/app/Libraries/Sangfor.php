<?php
namespace App\Libraries;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

class Sangfor 
{
    protected $client;
    protected $headers;
    protected $token = '';

    public function __construct()
    {
        $this->client = new Client([
            'verify' => false
        ]);

        $this->headers = ['Content-Type' => 'application/json'];
    }

    private function request(string $method, string $endpoint, array $params = [])
    {
        try {
            $url = rtrim($_ENV['FW_HOST'], '/') . '/' . ltrim($endpoint, '/');
            $res = $this->client->request($method, $url, $params);

            $status = $res->getStatusCode();
            $body   = $res->getBody()->getContents();
            $data   = $body ? json_decode($body, true) : [];

            return [
                'status'    => true,
                'http_code' => $status,
                'message'   => $res->getReasonPhrase(),
                'data'      => $data
            ];

        } catch (RequestException $e) {
            return [
                'status'    => false,
                'http_code' => $e->getCode() ?: 500,
                'message'   => $e->getMessage(),
                'data'      => []
            ];
        } catch (\Exception $e) {
            return [
                'status'    => false,
                'http_code' => 500,
                'message'   => $e->getMessage(),
                'data'      => []
            ];
        }
    }

    public function login()
    {
        $body = json_encode([
            'name'     => $_ENV['FW_USER'],
            'password' => $_ENV['FW_PASS']
        ]);

        $params = [
            'headers' => $this->headers,
            'body'    => $body,
        ];

        $result = $this->request('POST', 'api/v1/namespaces/public/login', $params);

        if ($result['status'] && isset($result['data']['data']['loginResult']['token'])) {
            $this->token = $result['data']['data']['loginResult']['token'];
        }

        return $result;
    }

    public function keepalive()
    {
        $headers = array_merge($this->headers, ['Cookie' => "token={$this->token}"]);

        $res = $this->request('GET', 'api/v1/namespaces/public/keepalive', [
            'headers' => $headers
        ]);

        if ($res['status'] && isset($res['data']['code']) && $res['data']['code'] == 1003) {
            return $this->login();
        }

        return $res;
    }

    public function getBlacklist(int $page)
    {
        $headers = array_merge($this->headers, ['Cookie' => "token={$this->token}"]);

        $res = $this->request('GET', "api/v1/namespaces/public/whiteblacklist?type=BLACK&_length=10&_start={$page}", [
            'headers' => $headers
        ]);

        if (!$res['status']) {
            return $this->login();
        }

        return $res;
    }

    public function getWhitelist(int $page)
    {
        $headers = array_merge($this->headers, ['Cookie' => "token={$this->token}"]);

        $res = $this->request('GET', "api/v1/namespaces/public/whiteblacklist?type=WHITE&_length=10&_start={$page}", [
            'headers' => $headers
        ]);

        if (!$res['status']) {
            return $this->login();
        }

        return $res;
    }

    public function createBlackWhite(array $data) 
    {
        $headers = [
            'Content-Type' => 'application/json',
            'Cookie'       => "token={$this->token}"
        ];

        $body = json_encode([
            'enable'      => $data['enable'],
            'type'        => $data['type'],
            'url'         => $data['ip_address'],
            'description' => $data['description']
        ]);

        return $this->request('POST', 'api/v1/namespaces/public/whiteblacklist', [
            'headers' => $headers,
            'body'    => $body
        ]);
    }

    public function tempBlock(array $data)
    {
        $headers = [
            'Content-Type' => 'application/json',
            'Cookie'       => "token={$this->token}"
        ];

        $body = json_encode([
            'ipType'    => 'SRC',
            'srcIP'     => [ $data['ip_address'] ],
            'blockTime' => $data['blockmode']
        ]);

        return $this->request('POST', 'api/batch/v1/namespaces/public/blockip', [
            'headers' => $headers,
            'body'    => $body
        ]);
    }

    public function deleteBlackWhite(array $data)
    {
        $headers = [
            'Content-Type' => 'application/json',
            'Cookie'       => "token={$this->token}"
        ];

        $body = json_encode([
            'enable'      => $data['enable'],
            'type'        => $data['type'],
            'url'         => $data['url'],
            'description' => $data['description']
        ]);

        return $this->request('DELETE', "api/v1/namespaces/public/whiteblacklist/{$data['url']}", [
            'headers' => $headers,
            'body'    => $body,
        ]);
    }
}
