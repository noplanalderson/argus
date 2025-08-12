<?php
namespace App\Modules;
/**
 * VirusTotal Scoring Calculator (PHP Version)
 */
class VirusTotalScoring
{
    private $weights;

    public function __construct()
    {
        // Bobot disesuaikan agar total = 1.0
        $this->weights = [
            'detection_rate'  => 0.4,  // 40%
            'reputation'      => 0.25, // 25%
            'sandbox_verdict' => 0.35  // 35%
        ];
    }

    private function calculateDetectionScore(int $malicious, int $total): float
    {
        if ($total === 0) {
            return 0.0;
        }

        $detection_rate = $malicious / $total;

        if ($detection_rate >= 0.1) {
            return 1.0;
        } elseif ($detection_rate >= 0.05) {
            return 0.7;
        } elseif ($detection_rate > 0) {
            return 0.4;
        } else {
            return 0.0;
        }
    }

    private function calculateReputationScore(int $reputation): float
    {
        if ($reputation <= -10) {
            return 1.0;
        } elseif ($reputation <= -5) {
            return 0.7;
        } elseif ($reputation < 0) {
            return 0.4;
        } else {
            return 0.0;
        }
    }

    private function calculateSandboxScore(array $sandbox_verdicts): float
    {
        if (empty($sandbox_verdicts)) {
            return 0.0;
        }

        $malicious_count = 0;
        $total_sandboxes = count($sandbox_verdicts);

        foreach ($sandbox_verdicts as $result) {
            if (isset($result['category']) && $result['category'] === 'malicious') {
                $malicious_count++;
            }
        }

        if ($malicious_count >= $total_sandboxes * 0.7) {
            return 1.0;
        } elseif ($malicious_count >= $total_sandboxes * 0.3) {
            return 0.7;
        } elseif ($malicious_count > 0) {
            return 0.4;
        } else {
            return 0.0;
        }
    }

    public function calculateFinalScore(array $vt_data): array
    {
        $attributes = $vt_data['attributes'] ?? [];
        $last_analysis_stats = $attributes['last_analysis_stats'] ?? [];
        $reputation = $attributes['reputation'] ?? 0;
        $sandbox_verdicts = $attributes['sandbox_verdicts'] ?? [];

        $detection_score = $this->calculateDetectionScore(
            $last_analysis_stats['malicious'] ?? 0,
            array_sum($last_analysis_stats) - 
            ($last_analysis_stats['type-unsupported'] ?? 0) - 
            ($last_analysis_stats['confirmed-timeout'] ?? 0) - 
            ($last_analysis_stats['timeout'] ?? 0) - 
            ($last_analysis_stats['failure'] ?? 0)
        );

        $reputation_score = $this->calculateReputationScore($reputation);
        $sandbox_score = $this->calculateSandboxScore($sandbox_verdicts);

        // Weighted final score tanpa sigma & yara
        $final_score = (
            $detection_score * $this->weights['detection_rate'] +
            $reputation_score * $this->weights['reputation'] +
            $sandbox_score * $this->weights['sandbox_verdict']
        );

        if ($final_score >= 0.7) {
            $risk_level = "HIGH";
        } elseif ($final_score >= 0.4) {
            $risk_level = "MEDIUM";
        } else {
            $risk_level = "LOW";
        }

        return [
            'final_score' => round($final_score, 3),
            'risk_level' => $risk_level
        ];
    }
}