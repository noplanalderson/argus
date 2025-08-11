<?php
namespace app\Modules;
use RouterOS\Client;
use RouterOS\Query;

class Mikrotik 
{
    protected $client;

    public function __construct()
    {
        $this->client = new Client([
            'host' => $_ENV['FW_HOST'],
            'user' => $_ENV['FW_USER'],
            'pass' => $_ENV['FW_PASS'],
            'port' => (int)$_ENV['FW_PORT']
        ]);
    }

    public function cmd($data)
    {
        if($data['blockmode'] == 'permanent') {

            $query = (new Query('/ip/firewall/address-list/add'))
                        ->equal('address', $data['ip_address'])
                        ->equal('list', 'blocklist')
                        ->equal('comment', $data['description']);
        } else {
            $query = (new Query('/ip/firewall/address-list/add'))
                        ->equal('address', $data['ip_address'])
                        ->equal('list', 'blocklist')
                        ->equal('timeout', $data['blockmode']. ' 00:00:00')
                        ->equal('comment', $data['description']);
        }

        return $this->client->query($query)->read();
    }
}