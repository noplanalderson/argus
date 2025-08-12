<?php
namespace App\Modules;
use App\Config\Database;
use Ramsey\Uuid\Uuid;
/**
 * Scoring Engine Class
 * Calculate overall IP's score based on Multiple-Source Threat Intelligence Platform
 * 
 * @package Argus Service
 * @author  Muhammad Ridwan Na'im <ridwannaim@tangerangkota.go.id>
 * @since 2025
 * @version 1.0
*/
class Scoring
{
    public $reports;

    public $firedTimes = 0;
    public array $dataMapping = [
        'abuseIpScore' => 0,
        'vtScore' => 0,
        'csScore' => 0,
        'blocklistScore' => 0,
        'countryName' => 'N/A',
        'isp' => 'N/A',
        'usageType' => 'N/A',
        'csClassifications' => [],
        'abuseCategories' => [],
        'isPublic' => false
    ];

    public $vtWeight = 0.2;

    public $crowdsecWeight = 0.3;
    
    public $abuseIpWeight = 0.4;

    public $blocklistWeight = 0.1;

    protected $histories = [];

    protected $sOverall = 0;

    protected $recentHistory = null;

    protected $decision = ['notification' => true, 'abuse_report' => true];

    public function __construct(array $reports, $firedTimes = 0)
    {
        $this->reports = $reports;
        $this->firedTimes = $firedTimes;
    }

    private function __normalizeScores($score, $maxScore)
    {
        if($maxScore == 0) {
            return 0;
        }
        return ($score / $maxScore) * 100;
    }

    private function __vtScoring($malicious, $suspicious, $undetected, $vtVotes, $total) {
        
        $malicious  = $this->__normalizeScores($malicious, $total);
        $suspicious = $this->__normalizeScores($suspicious, $total);
        $vtVotes    = $this->__normalizeScores($vtVotes, $total);
        $undetected    = $this->__normalizeScores($undetected, $total);
        
        $maliciousWeight = 0.5;    // 50%
        $suspiciousWeight = 0.25;   // 25%
        $vtVotesWeight = 0.05;  // 5%
        $vtUndetectedWeight = 0.2; // 2%

        $risk = ($malicious * $maliciousWeight) +
                ($suspicious * $suspiciousWeight) +
                ($undetected * $vtUndetectedWeight) +
                ($vtVotes * $vtVotesWeight);

        return round($risk, 0);
    }

    private function __csScoring($overallScore)
    {
        return ($overallScore / 5) * 100;
    }

    public function extractData()
    {
        if(!empty($this->reports['analyzer_reports'])) 
        {
            $dataMapping = $this->dataMapping;
            foreach ($this->reports['analyzer_reports'] as $ti) {
                if($ti['name'] == 'AbuseIPDB' && $ti['status'] == 'SUCCESS') {
                    $dataMapping['abuseIpScore'] = $ti['report']['data']['abuseConfidenceScore'] ?? 0;
                    $dataMapping['countryName'] = $ti['report']['data']['countryName'] ?? 'N/A';
                    $dataMapping['isp'] = $ti['report']['data']['isp'] ?? 'N/A';
                    $dataMapping['usageType'] = $ti['report']['data']['usageType'] ?? 'N/A';

                    $categories = [];
                    foreach ($ti['report']['categories_found'] as $key => $value) {
                        $categories[] = $key;
                    }

                    $dataMapping['abuseCategories'] = $categories;
                }
                
                if($ti['name'] == 'Crowdsec' && $ti['status'] == 'SUCCESS') {
                    $classifications = $ti['data_model']['additional_info']['classifications'] ?? [];

                    $classification = [];
                    if(!empty($classifications)) {

                        foreach ($classifications as $value) {
                            $classification[] = $value['name'];
                        }
                    }

                    if(empty($ti['report']['data']['countryName'])) {
                        $dataMapping['isp'] = $ti['report']['as_name'] ?? 'N/A';
                    }

                    if(empty($ti['report']['data']['usageType'])) {
                        $dataMapping['countryName'] = $ti['report']['location']['city'] ?? 'N/A';
                    }

                    $dataMapping = array_merge($dataMapping, [
                        'csScore' => $this->__csScoring($ti['report']['scores']['overall']['total'] ?? 0),
                        'csClassifications' => $classification
                    ]);
                }

                if($ti['name'] == 'VirusTotal_v3_Get_Observable' && $ti['status'] == 'SUCCESS') {
                    $vtStats = $ti['report']['data']['attributes']['last_analysis_stats'];
                    $vtVotes = $ti['report']['data']['attributes']['total_votes']['malicious'];
                    $countSuspicious = $vtStats['suspicious'] ?? 0;
                    $countMalicious = $vtStats['malicious'] ?? 0;
                    $countHarmless = $vtStats['harmless'] ?? 0;
                    $countUndetected = $vtStats['undetected'] ?? 0;
                    $countTotal = $countSuspicious + $countMalicious + $countHarmless + $countUndetected;
            
                    $dataMapping['vtScore'] = $this->__vtScoring($countMalicious, $countSuspicious, $countUndetected, $vtVotes, $countTotal);
                }
            }

            $dataMapping['isPublic'] = checkIPType($this->reports['observable_name']);

            $db = dba_open("/var/www/html/blocklist/argus-ipsets.cdb", "r", "cdb");
            if ($db !== false) {
                $foundCdb = dba_exists($this->reports['observable_name'], $db);
                $dataMapping['blocklistScore'] = $foundCdb ? 100 : 0;
            }

            dba_close($db);
        }

        $this->dataMapping = $dataMapping;
        
        $this->__historyChecking();

        return $this;
    }

    private function __historyChecking()
    {
        $db = (new Database())->getConnection();
        $stmt = $db->prepare("
            SELECT `a`.`history_id_uuid`, `b`.`ip_id_uuid`, `b`.`ip_address`, `a`.`overall_score`, `a`.`decision`, `a`.`created_at`
            FROM `tb_analysis_history` `a`
            INNER JOIN `tb_ip_address` `b` ON `a`.`ip_id_uuid` = `b`.`ip_id_uuid`
            WHERE `b`.`ip_address` = ?
            ORDER BY `a`.`created_at` DESC
            LIMIT 1
        ");
        $stmt->execute([$this->reports['observable_name']]);
        $history = $stmt->fetch();

        if ($history && isset($history['decision'])) {
            $history['decision'] = json_decode($history['decision'], true);
        }

        $this->recentHistory = $history ?: null;
    }

    private function isRecentlyScored()
    {
        if (!$this->recentHistory || empty($this->recentHistory['created_at'])) {
            return false;
        }

        $lastAnalysis = strtotime($this->recentHistory['created_at']);
        if ($lastAnalysis === false) {
            return false;
        }

        return (time() - $lastAnalysis) < (3 * 86400);
    }

    private function __writeHistory()
    {
        $db = (new Database())->getConnection();
        
        $uuid   = Uuid::uuid7()->toString();
        $historyUuid = Uuid::uuid7()->toString();
        $ip     = $this->reports['observable_name'];
        $isp    = $this->dataMapping['isp'];
        $location = $this->dataMapping['countryName'];
        $classification = json_encode(array_merge($this->dataMapping['abuseCategories'], $this->dataMapping['csClassifications']));
        $csScore = $this->dataMapping['csScore'];
        $vtScore = $this->dataMapping['vtScore'];
        $adbScore = $this->dataMapping['abuseIpScore'];
        $adbScore = $this->dataMapping['abuseIpScore'];
        $blocklistScore = $this->dataMapping['blocklistScore'];
        $decision = json_encode($this->decision);

        if(count($this->histories) == 0) {
            $stmt1 = $db->prepare(
                "INSERT INTO `tb_ip_address` (`ip_id_uuid`, `ip_address`, `isp`, `classification`, `location`) 
                VALUES (:uuid, :ip, :isp, :classification, :location)"
            );
            $stmt1->execute([
                ':uuid' => $uuid,
                ':ip' => $ip,
                ':isp' => $isp,
                ':classification' => $classification,
                ':location' => $location
            ]);

            $stmt2 = $db->prepare(
                "INSERT INTO `tb_analysis_history` 
                (`history_id_uuid`, `ip_id_uuid`, `crowdsec_score`, `vt_score`, `abuseip_score`, `blocklist_score`, `overall_score`, `decision`) 
                VALUES (:historyUuid, :uuid, :csScore, :vtScore, :adbScore, :blocklistScore, :overallScore, :decision)"
            );
            $stmt2->execute([
                ':historyUuid' => $historyUuid,
                ':uuid' => $uuid,
                ':csScore' => $csScore,
                ':vtScore' => $vtScore,
                ':adbScore' => $adbScore,
                ':blocklistScore' => $blocklistScore,
                ':overallScore' => $this->sOverall,
                ':decision' => $decision
            ]);
        } else {
            $uuid = $this->histories[0]['ip_id_uuid'];


            $stmt1 = $db->prepare("
                UPDATE `tb_ip_address` SET `isp` = :isp, `classification` = :classification, `location` = :location, `updated_at` = now() WHERE ip_id_uuid = :uuid
            ");
            $stmt1->execute([
                ':uuid' => $uuid,
                ':isp' => $isp,
                ':classification' => $classification,
                ':location' => $location
            ]);
            $stmt2 = $db->prepare(
                "INSERT INTO `tb_analysis_history` 
                (`history_id_uuid`, `ip_id_uuid`, `crowdsec_score`, `vt_score`, `abuseip_score`, `blocklist_score`, `overall_score`, `decision`) 
                VALUES (:historyUuid, :uuid, :csScore, :vtScore, :adbScore, :blocklistScore, :overallScore, :decision)"
            );
            $stmt2->execute([
                ':historyUuid' => $historyUuid,
                ':uuid' => $uuid,
                ':csScore' => $csScore,
                ':vtScore' => $vtScore,
                ':adbScore' => $adbScore,
                ':blocklistScore' => $blocklistScore,
                ':overallScore' => $this->sOverall,
                ':decision' => $decision
            ]);
        }
    }

    private function __decision()
    {
        if($this->sOverall < 30 && $this->firedTimes > 15) {
            // override keputusan berdasarkan firedTimes (SRP : Single Responsibility Principle)
            $decision = '3d';
        } elseif($this->sOverall < 30) {
            $decision = false;
        } elseif($this->sOverall >= 30 && $this->sOverall < 50) {
            $decision = '3d';
        } elseif($this->sOverall >= 50 && $this->sOverall < 70) {
            $decision = '7d';
        } else {
            $decision = 'permanent';
        }

        $this->decision = array_merge($this->decision, ['blockmode' => $decision]);
    }

    public function run()
    {
        if ($this->isRecentlyScored() && is_array($this->recentHistory)) {
            // Balikin hasil existing tanpa analisa ulang
            return [
                'scores'       => $this->recentHistory['overall_score'],
                'historyHits'  => 1,
                'histories'    => [$this->recentHistory],
                'firedTimes'   => $this->firedTimes,
                'ipaddress'    => $this->reports['observable_name'],
                'description'  => 'This IP was recently analyzed within the last 3 days.',
                'reference'    => 'http://172.16.9.148/jobs/'.$this->reports['id'].'/visualizer/Reputation',
                'data'         => array_merge(
                                    $this->dataMapping,
                                    ['decision' => $this->recentHistory['decision'] ?? ['notification' => true, 'abuse_report' => true]]
                                )
            ];
        }

        // Calculate weighted final risk score
        $sOverall = $this->dataMapping['vtScore'] * $this->vtWeight +
                    $this->dataMapping['abuseIpScore'] * $this->abuseIpWeight +
                    $this->dataMapping['blocklistScore'] * $this->blocklistWeight +
                    $this->dataMapping['csScore'] * $this->crowdsecWeight;

        if($this->recentHistory) {
            $this->sOverall = round(min($sOverall + 1, 100), 0);
        } else {
            $this->sOverall = round($sOverall, 0);
        }

        $this->__decision();
        $this->__writeHistory();

        return [
            'scores' => $this->sOverall,
            'historyHits' => $this->recentHistory ? 1 : 0,
            'histories' => $this->recentHistory ? [$this->recentHistory] : [],
            'firedTimes'   => $this->firedTimes,
            'ipaddress' => $this->reports['observable_name'],
            'description' => "IP analysis based on multiple threat intelligence (Scores {$this->sOverall})",
            'reference' => 'http://172.16.9.148/jobs/'.$this->reports['id'].'/visualizer/Reputation',
            'data' => array_merge(
                $this->dataMapping,
                ['decision' => $this->decision]
            )
        ];
    }

}