<?php
namespace App\Libraries;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

class Sangfor 
{
    protected $client;
    protected $headers;
    protected $token = '';
    protected $isLoggedIn = false;

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

    // Helper untuk auto-retry dengan login
    private function requestWithAuth(string $method, string $endpoint, array $params = [], int $retryCount = 0)
    {
        // Pastikan sudah login
        if (!$this->isLoggedIn) {
            $loginResult = $this->login();
            if (!$loginResult['status']) {
                return $loginResult;
            }
        }

        // Tambahkan token ke header
        $headers = array_merge(
            $params['headers'] ?? $this->headers, 
            ['Cookie' => "token={$this->token}"]
        );
        $params['headers'] = $headers;

        // Eksekusi request
        $res = $this->request($method, $endpoint, $params);

        // Jika token invalid (1003) dan belum retry, login ulang dan coba lagi
        if ($res['status'] && 
            isset($res['data']['code']) && 
            $res['data']['code'] == 1003 && 
            $retryCount < 1) {
            
            $this->isLoggedIn = false;
            $loginResult = $this->login();
            
            if ($loginResult['status']) {
                return $this->requestWithAuth($method, $endpoint, $params, $retryCount + 1);
            }
            
            return $loginResult;
        }

        return $res;
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
            $this->isLoggedIn = true;
        } else {
            $this->isLoggedIn = false;
        }

        return $result;
    }

    public function keepalive()
    {
        return $this->requestWithAuth('GET', 'api/v1/namespaces/public/keepalive');
    }

    public function getBlacklist(int $page)
    {
        return $this->requestWithAuth('GET', "api/v1/namespaces/public/whiteblacklist?type=BLACK&_length=10&_start={$page}");
    }

    public function getWhitelist(int $page)
    {
        return $this->requestWithAuth('GET', "api/v1/namespaces/public/whiteblacklist?type=WHITE&_length=10&_start={$page}");
    }

    public function createBlackWhite(array $data) 
    {
        $body = json_encode([
            'enable'      => $data['enable'],
            'type'        => $data['type'],
            'url'         => $data['ip_address'],
            'description' => $data['description']
        ]);

        return $this->requestWithAuth('POST', 'api/v1/namespaces/public/whiteblacklist', [
            'body' => $body
        ]);
    }

    public function tempBlock(array $data)
    {
        $body = json_encode([
            'ipType'    => 'SRC',
            'srcIP'     => [ $data['ip_address'] ],
            'blockTime' => $data['blockmode']
        ]);

        return $this->requestWithAuth('POST', 'api/batch/v1/namespaces/public/blockip', [
            'body' => $body
        ]);
    }

    public function deleteBlackWhite(array $data)
    {
        $body = json_encode([
            'enable'      => $data['enable'],
            'type'        => $data['type'],
            'url'         => $data['url'],
            'description' => $data['description']
        ]);

        return $this->requestWithAuth('DELETE', "api/v1/namespaces/public/whiteblacklist/{$data['url']}", [
            'body' => $body
        ]);
    }
}