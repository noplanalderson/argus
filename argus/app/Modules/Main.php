<?php
namespace App\Modules;
use App\Config\Config;

/**
 * Main Class of Microservice Decision
 * based on Mutiple-source Threat Intelligence Platforms
 * 
 * @package Mikroservices Decision
 * @author  Muhammad Ridwan Na'im <ridwannaim@tangerangkota.go.id>
 * @since 2025
 * @version 1.0
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
                    $ip = $this->request->get('ip');
                    $checkIP = new \App\Modules\CheckIP($ip);
                    $status = $checkIP->check();
                    setJSON([
                        'code' => 200,
                        'error' => null,
                        'message' => "Ok",
                        'results' => ['ip_address' => $ip, 'status' => $status]
                    ], 200);
                    break;

                case 'analyze':
                    $jobId = $this->request->post('job_id');
                    $firedTimes = $this->request->post('firedtimes');
                    $hash = $this->request->post('hash');
                    $type = $this->request->post('type');
                    $results = [];
                    if($type === 'ip')
                    {
                        $threatIntelResult = (new \App\Modules\Receiver($jobId))->exec();
                        if($threatIntelResult['status']) {
                            $scoring = new \App\Modules\Scoring($threatIntelResult['data'], $firedTimes);
                            $extract = $scoring->extractData();
                            $results = $extract->run();
                        }
                    }
                    else 
                    {
                        $threatIntelResult = (new \App\Modules\Receiver($jobId))->exec();
                        if(!empty($_ENV['OPENCTI_URL']) && !empty($_ENV['OPENCTI_API_KEY'])) {
                            $scoring = new \App\Modules\OpenCTI($hash);
                            $results = $scoring->run();
                            if($results['status'] === false || !empty($results['opencti']['errors'])) {
                                if($threatIntelResult['status']) {
                                    $scoring2 = new \App\Modules\HashScoring($threatIntelResult['data']);
                                    $results = $scoring2->run();
                                }
                            }
                        } else {
                            if($threatIntelResult['status']) {
                                $scoring2 = new \App\Modules\HashScoring($threatIntelResult['data']);
                                $results = $scoring2->run();
                            }
                        }
                    }
                    setJSON([
                        'code' => 200,
                        'error' => null,
                        'message' => "Ok",
                        'results' => $results
                    ], 200);
                    break;
                
                case 'action':
                    $post = $this->request->post();

                    if($_ENV['FW_TYPE'] == 'SANGFOR') {
                        $sangfor = new \App\Modules\Sangfor;
                        $sangfor->login();
                        $sangfor->keepalive();

                        // $blacklist = $sangfor->getBlacklist(10);
                        if($post['blockmode'] == 'permanent') {
                            $block = $sangfor->createblackwhite($post);
                        } else {
                            $block = $sangfor->tempblock($post);
                        }
                    } else {
                        $mikrotik = new \App\Modules\Mikrotik;
                        $block = $mikrotik->cmd($post);
                    }
                    setJSON([
                        'code' => 200,
                        'error' => null,
                        'message' => "Aman Kamerad 🫡!",
                        'result' => $block
                    ], 200);
                    break;
                
                case 'yeti':
                    $post = $this->request->post('observable');
                    $yeti = new \App\Modules\Yeti;
                    $yeti->getAccessToken();
                    $observableData = $yeti->getObservable($post);
                    setJSON($observableData, $observableData['code']);
                    break;

                case 'yeti_add':
                    $post = $this->request->post('observable');
                    $yeti = new \App\Modules\Yeti;
                    $yeti->getAccessToken();
                    $observableData = $yeti->addObservable($post);
                    setJSON($observableData, $observableData['code']);
                    break;

                default:
                    setJSON([
                        'code' => 200,
                        'error' => null,
                        'title' => "ARGUS Guard",
                        'description' => "Argus (Automated Reputation-based Global Untrusted Source-blocker) based on Multiple Threat Intelligence Source and Blocklist with Automatic Blocking to Sangfor NGFW or Mikrotik",
                        'author' => "Muhammad Ridwan Na'im <ridwannaim@tangerangkota.go.id>",
                        'version' => "1.0.0",
                        'availablePath' => [
                            '[GET] /home',
                            '[POST] /analyze',
                            '[POST] /action',
                            '[POST] /yeti',
                            '[POST] /yeti_add',
                        ]
                    ], 200);
                    break;
            }
        }
    }
}