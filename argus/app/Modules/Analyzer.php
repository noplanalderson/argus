<?php
namespace App\Modules;
use App\Config\Database;
use App\Libraries\CriminalIPScoring;
use App\Libraries\AdaptiveSAW;
use App\Libraries\MalwareBazaarScoring;
use App\Cores\DB;
use Ramsey\Uuid\Uuid;
/**
 * Observable Analyzer Engine Class
 * Calculate overall observable score based on Multiple-Source Threat Intelligence Platform
 * 
 * @package Argus Service
 * @author  Muhammad Ridwan Na'im <ridwannaim@tangerangkota.go.id>
 * @since 2025
 * @version 2.0.0
*/
class Analyzer
{
    public array $reports = [];

    protected array $successResources = [
        'hash' => [
            'virustotal' => false,
            'yaraify' => false,
            'malware_bazaar' => false,
            'malprobe' => false,
            'opencti' => false
        ],
        'ip' => [
            'virustotal' => false,
            'blocklist' => false,
            'abuseipdb' => false,
            'crowdsec' => false,
            'criminalip' => false,
            'opencti' => false
        ]
    ];

    protected array $data = [
        'id' => null,
        'observable' => null,
        'scores' => [
            'virustotal' => 0,
            'malware_bazaar' => 0,
            'yaraify' => 0,
            'malprobe' => 0,
            'criminalip' => 0,
            'blocklist' => 0,
            'crowdsec' => 0,
            'abuseipdb' => 0,
            'opencti' => 0,
            'overall' => 0
        ],
        'classification' => [],
        'decision' => [
            'notification' => true
        ]
    ];

    protected array $weight = [
        'hash' => [
            'virustotal' => 0.30,
            'yaraify' => 0.05,
            'malware_bazaar' => 0.15,
            'malprobe' => 0.25,
            'opencti' => 0.25
        ],
        'ip' => [
            'virustotal' => 0.05,
            'blocklist' => 0.25,
            'abuseipdb' => 0.20,
            'crowdsec' => 0.15,
            'criminalip' => 0.15,
            'opencti' => 0.20
        ]
    ];

    protected string $logFile;
    protected string $type = '';
    protected int $frequency = 0;

    public function __construct(array $reports, $type, $frequency = 0)
    {
        $this->reports = $reports;
        $this->type = $type;
        $this->frequency = $frequency;
        $this->data['observable'] = $reports['observable'] ?? null;
        $this->logFile = ROOTPATH . 'logs/argus_tip.log';
    }

    private function __normalizeScores($score, $maxScore)
    {
        if($maxScore == 0) {
            return 0;
        }
        return ($score / $maxScore) * 100;
    }

    private function logError(string $source, string $error): void
    {
        $message = sprintf(
            "[%s] [%s] %s%s",
            date('Y-m-d H:i:s'),
            $source,
            preg_replace('/\n/', '', $error),
            PHP_EOL
        );

        file_put_contents($this->logFile, $message, FILE_APPEND);
    }
    private function logInfo(string $source, string $info): void
    {
        $message = sprintf(
            "[%s] [%s] %s%s",
            date('Y-m-d H:i:s'),
            $source,
            preg_replace('/\n/', '', $info),
            PHP_EOL
        );

        file_put_contents($this->logFile, $message, FILE_APPEND);
    }
    
    protected function virusTotal()
    {
        $vt = new \App\Libraries\VirusTotalScoring();
        if(isset($this->reports['virustotal'])) {
            if($this->reports['virustotal']['success'] == true) {

                $this->successResources[$this->type]['virustotal'] = true;

                $vtResults = $this->reports['virustotal']['results']['data'];
                $score = $vt->calculateFinalScore($vtResults);
                $this->data['scores']['virustotal'] = round($this->__normalizeScores($score['final_score'], 1),2);

                if(!empty($vtResults['behaviour_summary']['data']))
                {
                    $this->data['classification']['virustotal'] = $vtResults['behaviour_summary']['data']['verdicts'];
                } 
                elseif(!empty($vtResults['sandbox_verdicts']))
                {
                    foreach ($vtResults['sandbox_verdicts'] as $key => $value) {
                        $classification['virustotal'][] = $value['malware_classification'];
                    }
                } else {
                    $this->data['classification']['virustotal'] = $vtResults['attributes']['type_tags'] ?? 'Unknown';
                }
            }
        }
    }

    protected function yaraify()
    {
        $clamavWeight   = 0.65;
        $yaraWeight     = 0.35;

        if(isset($this->reports['yaraify'])) {
            if($this->reports['yaraify']['success'] == true) {
                if($this->reports['yaraify']['results']['query_status'] === 'ok')
                {
                    $this->successResources['hash']['yaraify'] = true;

                    $yaraify = $this->reports['yaraify']['results']['data'];
                    $task = $yaraify['tasks'][0];
                    $clamav = $task['clamav_results'] ? 1 : 0;
                    $yaraCommunity = min(count($task['static_results']), 5) / 5;

                    $yaraScore = ($clamav * $clamavWeight) + ($yaraCommunity * $yaraWeight);
                    $this->data['scores']['yaraify'] = round($this->__normalizeScores($yaraScore, 1),2);
                    $this->data['classification']['yaraify'] = $task['clamav_results'] ?? ($task['static_results'][0]['rule_name'] ?? 'Unknown');
                }
            }
        }
    }

    protected function malwareBazaar()
    {
        if(isset($this->reports['malware_bazaar'])) {
            if($this->reports['malware_bazaar']['success'] == true) {
                if($this->reports['malware_bazaar']['results']['query_status'] === 'ok')
                {
                    $this->successResources['hash']['malware_bazaar'] = true;

                    $mbData = $this->reports['malware_bazaar']['results']['data'][0];
                    $mbScoring = new MalwareBazaarScoring();
                    $mbScore = $mbScoring->calculateFinalScore($mbData);
                    $this->data['scores']['malware_bazaar'] = round($mbScore['final_score'] * 100, 2);
                    $this->data['classification']['malware_bazaar'] = $mbData['tags'];
                }
            }
        }
    }

    protected function malprobe()
    {
        if(isset($this->reports['malprobe'])) {
            if($this->reports['malprobe']['success'] == true) {
                $results = $this->reports['malprobe']['results'];
                if(!empty($results))
                {
                    $this->successResources['hash']['malprobe'] = true;
                    $this->data['scores']['malprobe'] = round($results['score'] * 100, 2);
                    $this->data['classification']['malprobe'] = "{$results['label']} - {$results['type']}";
                }
            }
        }
    }

    protected function crowdsec()
    {
        if(isset($this->reports['crowdsec'])) {
            if($this->reports['crowdsec']['success'] == true) {
                if(!empty($this->reports['crowdsec']['results']))
                {
                    $this->successResources['ip']['crowdsec'] = true;

                    $results = $this->reports['crowdsec']['results'];
                    $this->data['scores']['crowdsec'] = round(($results['scores']['overall']['total']/5) * 100, 2);
                    $classifications = empty($results['behaviours']) ? ($results['classifications']['classifications'] ?? []) : [];

                    $classification = [];
                    if(!empty($classifications)) {

                        foreach ($classifications as $value) {
                            $classification[] = $value['label'];
                        }
                    }
                    $this->data['classification']['crowdsec'] = $classification;
                }
            }
        }
    }

    protected function criminalIp()
    {
        if(isset($this->reports['criminalip'])) {
            if($this->reports['criminalip']['success'] == true) {
                if($this->reports['criminalip']['results']['status'] == 200) {
                    $this->successResources['ip']['criminalip'] = true;
    
                    $data = $this->reports['criminalip']['results'];
                    $crimip = new CriminalIPScoring();
                    $score = $crimip->calculateScore($data);
                    $this->data['scores']['criminalip'] = $score['score'];
    
                    $this->data['classification']['criminalip'] = $data['tags'] ?? [];
                }
            }
        }
    }

    protected function abuseIp()
    {
        if(isset($this->reports['abuseipdb'])) {
            if($this->reports['abuseipdb']['success'] == true) {

                $this->successResources['ip']['abuseipdb'] = true;

                $data = $this->reports['abuseipdb']['results']['data'];
                $this->data['scores']['abuseipdb'] = $data['abuseConfidenceScore'];
                $this->data['classification']['abuseipdb'] = ['usage' => $data['usageType'], 'tor' => $data['isTor']] ?? 'Unknown';
            }
        }
    }

    protected function ipInfo()
    {
        $this->data['ip_info'] = ['isp' => 'N/A', 'country' => 'N/A', 'city' => 'N/A'];
        if(isset($this->reports['ipapi'])) {
            if($this->reports['ipapi']['success'] == true) {
                $this->data['ip_info'] = $this->reports['ipapi']['results'];
            }
        }
        
        $this->data['ip_info']['isPublic'] = checkIPType($this->reports['observable']);
    }

    protected function isBlacklisted()
    {
        $blocklistScore = 0;
        try {
            $db = dba_open(ROOTPATH . "blocklist/argus-ipsets.cdb", "r", "cdb");
            if ($db !== false) {
                $foundCdb = dba_exists($this->reports['observable'], $db);
                $blocklistScore = $foundCdb ? 100 : 0;
            }
            dba_close($db);
            
            $this->successResources['ip']['blocklist'] = true;
            
        } catch (\Throwable $th) {
            $this->logError('BLOCKLIST', $th->getMessage());
        }
        $this->data['scores']['blocklist'] = $blocklistScore;
    }

    protected function opencti()
    {
        if(isset($this->reports['opencti'])) {
            if($this->reports['opencti']['success'] == true) {
                $data = $this->reports['opencti']['results']['data']['stixCyberObservables']['edges'][0]['node'] ?? [];
                if(!empty($data)) {
                    
                    $this->successResources[$this->type]['opencti'] = true;

                    if(!empty($data['objectLabel']))
                    {
                        foreach ($data['objectLabel'] as $value) {
                            $this->data['classification']['opencti'][$data['createdBy']['name']][] = $value['value'];
                        }
                    }
                    $this->data['scores']['opencti'] = $data['x_opencti_score'] ?? 0;
                    $this->data["{$this->type}_info"]['opencti_description'] = $data['x_opencti_description'] ?? $this->reports['observable'];
                } 
            } else {
                $this->logError('OPENCTI', 'Failed to retrieve OpenCTI data for observable: ' . $this->reports['observable']);
            }
        }
    }

    protected function decision($previousBlock = false)
    {
        if($previousBlock === 0) {
            $decision = '1d';
        } elseif($previousBlock === '1d') {
            $decision = '3d';
        } elseif($previousBlock === '3d') {
            $decision = '7d';
        } elseif($previousBlock === '7d') {
            $decision = 'permanent';
        } else {
            if($this->data['scores']['overall']['score'] < 50 && $this->frequency >= 8) {
                // override keputusan berdasarkan frequency (SRP : Single Responsibility Principle)
                $decision = '7d';
            } elseif($this->data['scores']['overall']['score'] < 15) {
                $decision = false;
            } elseif($this->data['scores']['overall']['score'] >= 15 && $this->data['scores']['overall']['score'] < 30) {
                $decision = '1d';
            } elseif($this->data['scores']['overall']['score'] >= 30 && $this->data['scores']['overall']['score'] < 50) {
                $decision = '3d';
            } elseif($this->data['scores']['overall']['score'] >= 50 && $this->data['scores']['overall']['score'] < 70) {
                $decision = '7d';
            } else {
                $decision = 'permanent';
            }
        }

        $this->data['decision'] = array_merge($this->data['decision'], ['abuse_report' => true, 'blockmode' => $decision]);
    }

    public function scoring()
    {
        if(filter_var($this->reports['observable'], FILTER_VALIDATE_IP))
        {
            $this->ipInfo();
            $this->virusTotal();
            $this->crowdsec();
            $this->abuseIp();
            $this->criminalIp();
            $this->isBlacklisted();
            $this->opencti();

            $adaptiveSAW = new AdaptiveSAW($this->data['scores'], $this->weight[$this->type], $this->successResources[$this->type]);
            $scoreOverall = $adaptiveSAW->scoring();

            // Check IP histories
            $history = DB::table('tb_analysis_history')->select('tb_analysis_history.*, ip_address')
                            ->join('tb_ip_address', 'tb_ip_address.ip_id_uuid = tb_analysis_history.ip_id_uuid', 'inner')
                            ->where('ip_address', '=', $this->reports['observable'])->orderBy('tb_analysis_history.created_at', 'desc')->first();

            if (!empty($history)) {
                $history['decision'] = json_decode($history['decision'], true);
                $createdAt = strtotime($history['created_at']);
                $blocked = (int)$history['decision']['blockmode'];
                $unblock = $createdAt + ($blocked * 86400);
                $this->data['id'] = $history['ip_id_uuid'];
                if (strtotime("now") > $unblock) {

                    $this->data['scores']['overall'] = ['score' => round(min($history['overall_score'] + 1, 100), 0)];
                    if($blocked === 'permanent') {
                        $this->data['recentHistory'] = $history;
                    }
                    $this->decision($blocked);
                }
                else
                {
                    $this->data['recentHistory'] = $history ?: null;
                    $this->data['scores']['overall'] = $scoreOverall;
                    
                    $this->data['decision'] = $history['decision'];
                }

                if(empty($this->data['recentHistory']))
                {
                    try {
            
                        DB::table('tb_analysis_history')->insert([
                            'history_id_uuid' => Uuid::uuid7()->toString(),
                            'ip_id_uuid' => $history['ip_id_uuid'],
                            'vt_score' => $this->data['scores']['virustotal'],
                            'crowdsec_score' => $this->data['scores']['crowdsec'],
                            'abuseip_score' => $this->data['scores']['abuseipdb'],
                            'criminalip_score' => $this->data['scores']['criminalip'],
                            'blocklist_score' => $this->data['scores']['blocklist'],
                            'opencti_score' => $this->data['scores']['opencti'],
                            'overall_score' => round($this->data['scores']['overall']['score'], 2),
                            'decision' => json_encode($this->data['decision']),
                            'created_at' => date("Y-m-d H:i:s")
                        ]);
                    } catch (\Throwable $th) {
                        $this->logError('DB_OPERATION', $th->getMessage());
                    }
                }
                else 
                {
                    if($this->frequency > 7 && $this->data['scores']['overall']['score'] < 50) {
                        $this->decision();

                        DB::table("tb_analysis_history")->where('history_id_uuid', $history['history_id_uuid'])->update([
                            'decision' => json_encode($this->data['decision']),
                            'updated_at' => date("Y-m-d H:i:s")
                        ]);
                        
                        $this->data['recentHistory'] = (strtotime("now") > $unblock) ? null : $history;

                    } else {
                        $this->logInfo('INFO', 'No update made. IP ' . $this->reports['observable'] . ' is still under block period.');
                    }
                }
            } else {
                try {
                    $this->data['scores']['overall'] = $scoreOverall;
                    
                    $this->decision();

                    DB::beginTransaction();
                    $ipId = Uuid::uuid7()->toString();
                    $this->data['id'] = $ipId;
                    $this->data['scores']['overall'] = $scoreOverall;
                    $country = $this->data['ip_info']['country'] ?? 'N/A';
                    $city = $this->data['ip_info']['city'] ?? 'N/A';
                    DB::table('tb_ip_address')->insert([
                        'ip_id_uuid' => $ipId,
                        'ip_address' => $this->reports['observable'],
                        'isp' => $this->data['ip_info']['isp'] ?? 'Unknown',
                        'location' => "{$country} - {$city}",
                        'classification' => json_encode($this->data['classification']),
                        'created_at' => date("Y-m-d H:i:s")
                    ]);
                    DB::table('tb_analysis_history')->insert([
                        'history_id_uuid' => Uuid::uuid7()->toString(),
                        'ip_id_uuid' => $ipId,
                        'vt_score' => $this->data['scores']['virustotal'],
                        'crowdsec_score' => $this->data['scores']['crowdsec'],
                        'abuseip_score' => $this->data['scores']['abuseipdb'],
                        'criminalip_score' => $this->data['scores']['criminalip'],
                        'blocklist_score' => $this->data['scores']['blocklist'],
                        'opencti_score' => $this->data['scores']['opencti'],
                        'overall_score' => round($scoreOverall['score'], 2),
                        'decision' => json_encode($this->data['decision']),
                        'created_at' => date("Y-m-d H:i:s")
                    ]);
                    DB::commit();
                } catch (\Throwable $th) {
                    DB::rollback();
                    $this->logError('DB_OPERATION', $th->getMessage());
                }
            }
        }
        else
        {
            $this->virusTotal();
            $this->yaraify();
            $this->malwareBazaar();
            $this->malprobe();
            $this->opencti();

            
            $adaptiveSAW = new AdaptiveSAW($this->data['scores'], $this->weight[$this->type], $this->successResources[$this->type]);
            $scoreOverall = $adaptiveSAW->scoring();

            $this->data['scores']['overall'] = $scoreOverall;

            $history = DB::table('tb_file_hash')->select('*')->where('file_hash', $this->reports['observable'])->first();

            if (!empty($history['hash_id'])) {
                
                $lastAnalysis   = strtotime($history['created_at']);
                $reanalyzeTime  = $_ENV['FORCE_REANALYZE'] * 24 * 60 * 60;
                $unblock        = $lastAnalysis + $reanalyzeTime;

                if (strtotime("now") > $unblock) {
                    $hashId = Uuid::uuid7()->toString();
                    $this->data['id'] = $hashId;
                    try {
                        DB::table(table: 'tb_file_hash')->insert([
                            'hash_id' => $hashId,
                            'file_hash' => $this->reports['observable'],
                            'observable_name' => $this->reports['observable'],
                            'classification' => json_encode($this->data['classification']),
                            'vt_score' => $this->data['scores']['virustotal'],
                            'mb_score' => $this->data['scores']['malware_bazaar'],
                            'yara_score' => $this->data['scores']['yaraify'],
                            'malprobe_score' => $this->data['scores']['malprobe'],
                            'opencti_score' => $this->data['scores']['opencti'],
                            'overall_score' => round($scoreOverall['score'], 2),
                            'decision' => json_encode($this->data['decision']),
                            'created_at' => date("Y-m-d H:i:s")
                        ]);
                    } catch (\Throwable $th) {
                        $this->logError('DB_OPERATION', $th->getMessage());
                    }
                    $this->data['recentHistory'] = null;
                } else {
                    $this->data['recentHistory'] = $history;
                }
            } else {
                $hashId = Uuid::uuid7()->toString();
                $this->data['id'] = $hashId;
                try {
                    DB::table(table: 'tb_file_hash')->insert([
                        'hash_id' => $hashId,
                        'file_hash' => $this->reports['observable'],
                        'observable_name' => $this->reports['observable'],
                        'classification' => json_encode($this->data['classification']),
                        'vt_score' => $this->data['scores']['virustotal'],
                        'mb_score' => $this->data['scores']['malware_bazaar'],
                        'yara_score' => $this->data['scores']['yaraify'],
                        'malprobe_score' => $this->data['scores']['malprobe'],
                        'opencti_score' => $this->data['scores']['opencti'],
                        'overall_score' => round($scoreOverall['score'], 2),
                        'decision' => json_encode($this->data['decision']),
                        'created_at' => date("Y-m-d H:i:s")
                    ]);
                } catch (\Throwable $th) {
                    $this->logError('DB_OPERATION', $th->getMessage());
                }
            }
        }

        return $this;
    }

    public function exec()
    {
        $success = 0;
        foreach ($this->successResources[$this->type] as $value) {
            if($value) $success++;
        }

        return array_merge($this->data, [
            'type' => $this->type, 
            'description' => strtoupper($this->type) . " analysis based on multiple TIPs (Scores {$this->data['scores']['overall']['score']})",
            'success_source' => $success.'/'.count($this->successResources[$this->type])
        ]);
    }
}