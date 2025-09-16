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
    // protected array $weights = [
    //     'hash' => [
    //         'virustotal' => 0.30,
    //         'yaraify' => 0.05,
    //         'malware_bazaar' => 0.15,
    //         'malprobe' => 0.25,
    //         'opencti' => 0.25
    //     ],
    //     'ip' => [
    //         'virustotal' => 0.05,
    //         'blocklist' => 0.25,
    //         'abuseipdb' => 0.20,
    //         'crowdsec' => 0.15,
    //         'criminalip' => 0.15,
    //         'opencti' => 0.20
    //     ]
    // ];

    protected $adjustedWeights = [];

    public function __construct($scores, $weights, $criteriaSuccess)
    {
        $this->scores = $scores;
        $this->weights = $weights;
        $this->criteriaSuccess = $criteriaSuccess;
        $this->adjustedWeights = $this->weights;
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

        $scoreOverall = 0;
        foreach ($this->adjustedWeights as $key => $weight) {
            if (!empty($this->criteriaSuccess[$key])) {
                $scoreOverall += ($this->scores[$key] * $weight);
            }
        }

        return [
            'score' => round($scoreOverall, 2),
            'weights' => [$this->adjustedWeights, $this->criteriaSuccess]
        ];
    }
}