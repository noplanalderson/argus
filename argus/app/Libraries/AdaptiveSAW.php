<?php
namespace App\Libraries;

/**
 * Adaptive SAW Library for Threat Intelligence Platform
 * 
 * @package Argus Service
 * @author  Muhammad Ridwan Na'im <ridwannaim@tangerangkota.go.id>
 * @since   2025
 * @version 1.0.0
 */
class AdaptiveSAW
{
    protected $weights = [];
    protected $scores = [];
    protected $criteriaSuccess = [];
    protected $adjustedWeights = [];
    protected $wazuhRule = [];

    public function __construct($scores, $weights, $criteriaSuccess, $wazuhRule = [])
    {
        $this->scores = $scores;
        $this->weights = $weights;
        $this->criteriaSuccess = $criteriaSuccess;
        $this->adjustedWeights = $this->weights;
        $this->wazuhRule = $wazuhRule;
    }

    protected function weightAdjustment()
    {
        $failureWeightSum = 0;
        $successKeys = [];

        foreach ($this->weights as $key => $weight) {
            if (empty($this->criteriaSuccess[$key])) {
                $failureWeightSum += $weight;
                $this->adjustedWeights[$key] = 0;
            } else {
                $successKeys[] = $key;
            }
        }

        $successCount = count($successKeys);
        if ($successCount > 0 && $failureWeightSum > 0) {
            $redistribution = $failureWeightSum / $successCount;
            foreach ($successKeys as $key) {
                $this->adjustedWeights[$key] += $redistribution;
            }
        }
    }

    public function scoring()
    {
        $this->weightAdjustment();

        $tipScore = 0;
        foreach ($this->adjustedWeights as $key => $weight) {
            if (!empty($this->criteriaSuccess[$key])) {
                $tipScore += ($this->scores[$key] * $weight);
            }
        }

        $wazuhScore = new WazuhRuleScoring($this->wazuhRule);
        $wazuhRuleScore = ($wazuhScore->scoring() / 1.0) * 100;

        $scoreOverall = ($tipScore * 0.4) + ($wazuhRuleScore * 0.6);

        return [
            'score' => round($scoreOverall, 2),
            'wazuh_rule_score' => round($wazuhRuleScore, 2),
            'tip_score' => round($tipScore, 2),
            'weights' => [$this->adjustedWeights, $this->criteriaSuccess]
        ];
    }
}