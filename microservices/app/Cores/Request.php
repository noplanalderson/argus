<?php
namespace App\Cores;

class Request
{
    protected $headers;
    protected $body;

    public function __construct()
    {
        $this->headers = $this->getAllHeaders();
        $this->body    = $this->getJsonBody();
    }

    /**
     * Ambil semua headers
     */
    protected function getAllHeaders()
    {
        if (function_exists('getallheaders')) {
            return getallheaders();
        }

        // fallback untuk PHP di FPM CGI yang nggak support getallheaders()
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (str_starts_with($name, 'HTTP_')) {
                $headerName = str_replace('_', '-', substr($name, 5));
                $headers[$headerName] = $value;
            }
        }
        return $headers;
    }

    /**
     * Ambil body JSON sebagai array
     */
    protected function getJsonBody()
    {
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';

        if ($this->isJson() !== false) {
            $raw = file_get_contents('php://input');
            $data = json_decode($raw, true);
            return $data ?? [];
        }

        return [];
    }

    /**
     * Ambil query string parameter (GET)
     */
    public function get($key, $default = null)
    {
        return $_GET[$key] ?? $default;
    }

    /**
     * Ambil dari JSON body
     */
    public function post($key = false, $default = null)
    {
        return (!$key) ? $this->body : ($this->body[$key] ?? $default);
    }

    /**
     * Ambil semua header
     */
    public function headers()
    {
        return $this->headers;
    }

    /**
     * Ambil header tertentu
     */
    public function header($key, $default = null)
    {
        return $this->headers[$key] ?? $default;
    }

    /**
     * Ambil semua body
     */
    public function all()
    {
        return $this->body;
    }

    public function isJson()
    {
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        return stripos($contentType, 'application/json') !== false;
    }

}
