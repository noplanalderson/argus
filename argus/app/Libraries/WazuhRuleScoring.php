<?php
namespace App\Libraries;

/**
 * Wazuh Rule Scoring
 * 
 * @package Argus Service
 * @author  Muhammad Ridwan Na'im <ridwannaim@tangerangkota.go.id>
 * @since   2025
 * @version 1.0.0
 */
class WazuhRuleScoring
{
    private $rule = [];
    const DEFAULT_WEIGHTS = [
        'severity'      => 0.60,    // Rule level (1-15)
        'frequency'     => 0.20,    // Berapa kali fired dalam periode tertentu
        'groups'        => 0.30,    // Kategori threat
    ];
    
    private $response_code = 0;

    public function __construct(array $rule)
    {
        $this->rule = $rule;
        $this->response_code = $rule['response_code'] ?? 0;
    }

    private function calculateResponseCode()
    {
        $valid_response = [200, 201, 202, 204];
        $redirect_response = [300, 301, 302, 303, 304];
        $invalid_response = [400, 401, 403, 404];
        $error_response = [500, 502, 503,504];
        
        if(in_array($this->response_code, $valid_response)) {
            $score = 1.0;
        } elseif(in_array($this->response_code, $redirect_response)) {
            $score = 0.5;
        } elseif(in_array($this->response_code, $error_response)) {
            $score = 0.8;
        } elseif(in_array($this->response_code, $invalid_response)) {
            $score = 0.3;
        }

        return $score;
    }

    private function calculateSeverityScore(): float
    {
        $level = $this->rule['level'] ?? 0;
        $severityScore = $level / 15;
        // Calculate rule level with response code
        if(!in_array('web', $this->rule['groups'] ?? [])) {
            return $severityScore;
        }
        return min(($this->calculateResponseCode() + $severityScore) / 2, 1.0);
    }

    private function calculateFrequency(): float
    {
        $frequency = $this->rule['frequency'] ?? 1;
        // Exponential curve: semakin sering fired, semakin tinggi score
        // Capped at 100 times
        return min(log1p($frequency) / log1p(100), 1.0);
    }

    private function calculateGroupScore(): float
    {
        $groups = $this->rule['groups'] ?? [];
        $groups = !empty(array_intersect(['recon', 'path_traversal', 'web_scan'], $groups)) ? ['recon'] : $groups;
        $groupScores = [
            'malware'               => 1.0,
            'yara'                  => 1.0,
            'authentication_success'=> 0.9,
            'webshell'              => 0.8,
            'seo_cloaking'          => 0.8,
            'ssrf'                  => 0.8,
            'lfi'                   => 0.8,
            'rfi'                   => 0.8,
            'command_injection'     => 0.8,
            'dos'                   => 0.7,
            'content_violation'     => 0.7,
            'credential_breach'     => 0.7,
            'sql_injection'         => 0.7,
            'xss'                   => 0.7,
            'bruteforce'            => 0.6,
            'recon'                 => 0.5,
            'spam'                  => 0.5,
            'firewall_drop'         => 0.5,
            'authentication_failures'=> 0.5,
            'sensitive_file'        => 0.5,
            'file_monitoring'       => 0.0
        ];
        $score = 0.0;
        $countGroups = 0;
        foreach ($groups as $group) {
            if(array_key_exists($group, $groupScores))
            {
                $countGroups++;
                $score += $groupScores[$group];
            }
        }
        $score = min($score / $countGroups, 1.0);
        return round($score, 1);
    }

    public function scoring()
    {
        $severityScore = $this->calculateSeverityScore();
        $frequencyScore = $this->calculateFrequency();
        $groupScore = $this->calculateGroupScore();

        $finalScore = (
            ($severityScore * self::DEFAULT_WEIGHTS['severity']) +
            ($frequencyScore * self::DEFAULT_WEIGHTS['frequency']) +
            ($groupScore * self::DEFAULT_WEIGHTS['groups'])
        ) / array_sum(self::DEFAULT_WEIGHTS);

        return round($finalScore, 2);
    }
}