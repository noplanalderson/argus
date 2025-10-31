<?php
namespace App\Modules;
use App\Config\Config;
use App\Config\TIPConfig;
use App\Libraries\ArgusAggregator;

/**
 * Main Class of Argus (Adaptive Reputation & Guarding Unified System)
 * based on Mutiple-source Threat Intelligence Platforms
 * 
 * @package Argus
 * @author  Muhammad Ridwan Na'im <ridwannaim@tangerangkota.go.id>
 * @since 2025
 * @version 2.0
*/
class Main
{
    protected $auth;

    protected $request;

    public function __construct()
    {
        $authConfig = new Config;
        $this->auth = $authConfig->auth;
        $this->request = new \App\Cores\Request;
    }

    public function run()
    {
        date_default_timezone_set('Asia/Jakarta');
        $headers = getallheaders();

        if (
            !isset($headers['Authorization']) ||
            !preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches) ||
            $matches[1] !== $this->auth['api_auth']['secret_key']
        ) {
            setJSON(['code' => 401, 'error' => 'Unauthorized', 'message' => 'Gome home, you\'re drunk! 🤪'], 401);
        } else {
            $requestUri = $_SERVER['REQUEST_URI'] ?? '/';
            $path = parse_url($requestUri, PHP_URL_PATH) ?? '';

            if (strpos($path, '/index.php') === 0) {
                $path = substr($path, strlen('/index.php'));
            }

            $segments = explode('/', trim($path, '/'));
            $segment = isset($segments[0]) ? $segments[0] : null;

            switch ($segment) {
                case 'home':
                    setJSON([
                        'code' => 200,
                        'error' => null,
                        'message' => "Silent is Golden 😊",
                        'path' => $segment
                    ], 200);
                    break;

                case 'check':
                    $observable = $this->request->get('observable');
                    $observableType = filter_var($observable, FILTER_VALIDATE_IP) ? 'ip' : 'hash';
                    $checkObservable = new \App\Modules\CheckObservable($observable, $observableType);
                    $status = $checkObservable->check();
                    setJSON([
                        'code' => 200,
                        'error' => null,
                        'message' => "Ok",
                        'results' => ['observable' => $observable, 'status' => $status]
                    ], 200);
                    break;
                
                case 'action':
                    $post = $this->request->post();

                    if($_ENV['FW_TYPE'] == 'SANGFOR') {
                        $sangfor = new \App\Libraries\Sangfor;
                        $sangfor->login();
                        $sangfor->keepalive();

                        // $blacklist = $sangfor->getBlacklist(10);
                        if($post['blockmode'] == 'permanent') {
                            $block = $sangfor->createblackwhite($post);
                        } else {
                            $block = $sangfor->tempblock($post);
                        }
                    } else {
                        $mikrotik = new \App\Libraries\Mikrotik;
                        $block = $mikrotik->cmd($post);
                    }
                    setJSON([
                        'code' => 200,
                        'error' => null,
                        'message' => "Ready, comrade 🫡!",
                        'result' => $block
                    ], 200);
                    break;
                
                case 'yeti':
                    $observable = $this->request->post('observable');
                    $type = $this->request->post('type');
                    $yeti = new \App\Modules\Yeti;
                    $yeti->getAccessToken();
                    $observableData = $yeti->getObservable($observable);
                    if($observableData['code'] === 200) {
                        if(empty($observableData['data']['known'])) {
                            $observableData = $yeti->addObservable($observable, $type);
                        }
                    }
                    setJSON($observableData, $observableData['code']);
                    break;

                case 'analyze':
                    $observable = $this->request->post('observable');
                    $frequency = $this->request->post('frequency', 0);

                    // Validate if $observable is a valid IP or SHA1
                    if (
                        !filter_var($observable, FILTER_VALIDATE_IP) &&
                        !preg_match('/^[a-f0-9]{40}$/i', $observable) &&   // SHA1
                        !preg_match('/^[a-f0-9]{64}$/i', $observable) &&   // SHA256
                        !preg_match('/^[a-f0-9]{96}$/i', $observable) &&   // SHA384
                        !preg_match('/^[a-f0-9]{32}$/i', $observable)      // SHA128 (MD5)
                    ) {
                        setJSON([
                            'code' => 400,
                            'error' => 'Bad Request',
                            'message' => 'Observable must be a valid IP address or SHA hash.'
                        ], 400);
                        break;
                    }

                    $type = filter_var($observable, FILTER_VALIDATE_IP) ? 'ip' : 'hash';
                    $sources = TIPConfig::getSources($type);
                    $agg = new ArgusAggregator($observable, $sources);
                    $results = $agg->run();

                    $analyzer = new Analyzer($results, $type, $frequency);
                    $analyzerResults = $analyzer->scoring()->exec();

                    setJSON([
                        'code' => 200,
                        'error' => null,
                        'message' => 'Ok',
                        'results' => $analyzerResults
                    ], 200);
                    break;
                
                case 'blocklist':
                    $blocklist = new \App\Modules\Blocklist(
                        $this->request->post('date_start'),
                        $this->request->post('date_end'),
                        $this->request->post('limit', 10),
                        $this->request->post('offset', 0)
                    );
                    $results = $blocklist->getBlocklist();
                    setJSON($results, 200);
                    break;

                case 'jobs':
                    $jobs = new \App\Modules\Jobs(
                        $this->request->post('date_start'),
                        $this->request->post('date_end'),
                        $this->request->post('limit', 10),
                        $this->request->post('offset', 0)
                    );
                    $results = $jobs->getJobs();
                    setJSON($results, 200);
                    break;

                default:
                    setJSON([
                        'code' => 200,
                        'error' => null,
                        'title' => "ARGUS",
                        'description' => "Argus (Adaptive Reputation & Guarding Unified System) based on Multiple Threat Intelligence Source and Blocklist with Automatic IP Blocker to Sangfor NGFW or Mikrotik",
                        'author' => "Muhammad Ridwan Na'im <ridwannaim@tangerangkota.go.id>",
                        'version' => "2.2.0",
                        'endpoints' => [
                            [
                                'method' => 'GET',
                                'path' => '/home',
                                'description' => 'Homepage endpoint',
                                'params' => []
                            ],
                            [
                                'method' => 'GET', 
                                'path' => '/check',
                                'description' => 'Check observable status',
                                'params' => [
                                    'observable' => 'IP address or file hash'
                                ]
                            ],
                            [
                                'method' => 'POST',
                                'path' => '/analyze',
                                'description' => 'Analyze observable threat score',
                                'params' => [
                                    'observable' => 'IP address or file hash',
                                    'frequency' => 'Number of occurrences (optional)'
                                ]
                            ],
                            [
                                'method' => 'POST',
                                'path' => '/action',
                                'description' => 'Block/unblock IP in firewall', 
                                'params' => [
                                    'blockmode' => 'permanent/temporary',
                                    'ip' => 'IP address to block/unblock',
                                    'action' => 'block/unblock'
                                ]
                            ],
                            [
                                'method' => 'POST',
                                'path' => '/blocklist',
                                'description' => 'Get blocked IP list',
                                'params' => [
                                    'date_start' => 'Start date',
                                    'date_end' => 'End date',
                                    'limit' => 'Number of records (default: 10)',
                                    'offset' => 'Offset for pagination (default: 0)'
                                ]
                            ],
                            [
                                'method' => 'POST', 
                                'path' => '/jobs',
                                'description' => 'Get job history',
                                'params' => [
                                    'date_start' => 'Start date',
                                    'date_end' => 'End date', 
                                    'limit' => 'Number of records (default: 10)',
                                    'offset' => 'Offset for pagination (default: 0)'
                                ]
                            ],
                            [
                                'method' => 'POST',
                                'path' => '/yeti',
                                'description' => 'Get observable from YETI',
                                'params' => [
                                    'observable' => 'IP address or file hash',
                                    'type' => 'Observable type'
                                ]
                            ]
                        ]
                    ], 200);
                    break;
            }
        }
    }
}