<?php
namespace App\Config;

class Config
{    
    public $auth;
    public function __construct()
    {
        $this->auth = [
            'api_auth' => [
                'enabled'        => true,
                'token_lifetime' => 0,
                'secret_key'     => $_ENV['API_AUTH_TOKEN'],
                'header_name'    => 'Authorization'
            ],
        ];
    }
}