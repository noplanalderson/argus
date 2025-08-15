<?php
namespace App\Modules;
use App\Config\Database;
use Ramsey\Uuid\Uuid;
/**
 * Hash Scoring Engine Class
 * Calculate overall file hash score based on Multiple-Source Threat Intelligence Platform
 * 
 * @package Argus Service
 * @author  Muhammad Ridwan Na'im <ridwannaim@tangerangkota.go.id>
 * @since 2025
 * @version 1.0
*/
class HashScoring
{
    public $reports;

    public array $dataMapping = [
        'id' => null,
        'vtScore' => 0,
        'malprobeScore' => 0,
        'mbScore' => 0,
        'yaraScore' => 0,
        'classification' => []
    ];

    protected $vtWeight = 0.35;

    protected $mbWeight = 0.25;

    protected $malprobeWeight = 0.3;

    protected $yaraWeight = 0.2;

    protected $overallScore = 0;

    protected $decision = ['notification' => true, 'reporting' => true];

    public function __construct(array $reports)
    {
        $this->reports = $reports;
    }

    private function __normalizeScores($score, $maxScore)
    {
        if($maxScore == 0) {
            return 0;
        }
        return ($score / $maxScore) * 100;
    }

    private function __scoring(array $reports)
    {
        if(!empty($this->reports['analyzer_reports'])) 
        {
            $vtScoring = new VirusTotalScoring();

            $classification = [
                'virus_total' => [],
                'yara' => [],
                'malware_bazaar' => []
            ];
            foreach ($this->reports['analyzer_reports'] as $ti) {

                // VirusTotal
                if($ti['name'] == 'VirusTotal_v3_Get_Observable' && $ti['status'] == 'SUCCESS') 
                {
                    $vtScore = $vtScoring->calculateFinalScore($ti['report']['data']);
                    $this->dataMapping['vtScore'] = $this->__normalizeScores($vtScore['final_score'], 1);

                    if(!empty($ti['report']['behaviour_summary']['data']))
                    {
                        $classification['virus_total'] = $ti['report']['behaviour_summary']['data']['verdicts'];
                    } 
                    elseif(!empty($ti['report']['data']['sandbox_verdicts']))
                    {
                        foreach ($ti['report']['data']['sandbox_verdicts'] as $key => $value) {
                            $classification['virus_total'][] = $value['malware_classification'];
                        }
                    } else {
                        $classification['virus_total'] = $ti['report']['data']['attributes']['type_tags'] ?? 'Unknown';
                    }
                }

                // YARAify
                if($ti['name'] == 'YARAify_Search' && $ti['status'] == 'SUCCESS') 
                {
                    $clamavWeight = 0.65;
                    $yaraWeight = 0.35;

                    if(!empty($ti['report']['data']['tasks'])) 
                    {
                        $task = $ti['report']['data']['tasks'][0];
                        $clamav = $task['clamav_results'] ? 1 : 0;
                        $yaraCommunity = min(count($task['static_results']), 5) / 5;

                        $yaraScore = ($clamav * $clamavWeight) + ($yaraCommunity * $yaraWeight);
                        $this->dataMapping['yaraScore'] = $this->__normalizeScores($yaraScore, 1);
                        $classification['yara'] = $task['clamav_results'] ?? ($task['static_results'][0]['rule_name'] ?? 'Unknown');
                    }
                }

                if($ti['name'] == 'MalwareBazaar_Get_Observable' && $ti['status'] == 'SUCCESS') 
                {
                    if(!empty($ti['report']['data']))
                    {
                        $mbScoring = new MalwareBazaarScoring();
                        $mbScore = $mbScoring->calculateFinalScore($ti);
                        $this->dataMapping['mbScore'] = round($mbScore['final_score'] * 100, 2);
                        $classification['malware_bazaar'] = $ti['report']['data'][0]['tags'];
                    }
                }

                if($ti['name'] == 'Malprob' && $ti['status'] == 'SUCCESS') 
                {
                    if(!empty($ti['report']))
                    {
                        $this->dataMapping['malprobeScore'] = round($ti['report']['score'] * 100, 2);
                        $classification['malprobe'] = "{$ti['report']['label']} - {$ti['report']['type']}";
                    }
                }
            }

            $this->dataMapping['classification'] = $classification;
        }
    }

    private function _saveResults()
    {
        $db = (new Database())->getConnection();
        
        $uuid   = Uuid::uuid7()->toString();

        $stmt = $db->prepare("INSERT INTO `tb_file_hash` (
                    `hash_id`, `file_hash`, `observable_name`, `classification`, `malprobe_score`,
                    `vt_score`, `mb_score`, `yara_score`, `opencti_score`, `overall_score`, `decision`) VALUES
                    (:hash_id, :file_hash, :observable_name, :classification, :malprobe_score,
                    :vt_score, :mb_score, :yara_score, :opencti_score, :overall_score, :decision)");
        $stmt->execute([
            ':hash_id' => $uuid,
            ':file_hash' => $this->reports['observable_name'],
            ':observable_name' => $this->reports['observable_name'],
            ':classification' => json_encode($this->dataMapping['classification']),
            ':malprobe_score' => $this->dataMapping['malprobeScore'],
            ':vt_score' => $this->dataMapping['vtScore'],
            ':mb_score' => $this->dataMapping['mbScore'],
            ':yara_score' => $this->dataMapping['yaraScore'],
            ':opencti_score' => null,
            ':overall_score' => $this->overallScore,
            ':decision' => json_encode($this->decision)
        ]);
    }

    public function run()
    {
        $this->__scoring($this->reports);

        $this->overallScore = $this->dataMapping['vtScore'] * $this->vtWeight +
                    $this->dataMapping['mbScore'] * $this->mbWeight +
                    $this->dataMapping['malprobeScore'] * $this->malprobeWeight +
                    $this->dataMapping['yaraScore'] * $this->yaraWeight;
        $scores = round($this->overallScore, 0);

        $this->_saveResults();

        return [
            'status' => true,
            'type' => 'hash',
            'opencti' => [],
            'scores' => $scores,
            'hash' => $this->reports['observable_name'],
            'description' => "Hash analysis based on multiple threat intelligence (Scores {$scores})",
            'reference' => "{$_ENV['INTELOWL_URL']}/jobs/{$this->reports['id']}/raw/analyzer",
            'data' => array_merge(
                $this->dataMapping,
                ['decision' => $this->decision]
            )
        ];
    }
}