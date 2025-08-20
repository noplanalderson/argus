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

    public function __construct($scores, $weights, $criteriaSuccess)
    {
        $this->scores = $scores;
        $this->weights = $weights;
        $this->criteriaSuccess = $criteriaSuccess;
    }

    protected function weightAdjustment()
    {
        $criteriaSuccess = array_sum($this->criteriaSuccess);

        $sumWeightFailureCriteria = 0;
        foreach ($this->weights as $key => $weight) {
            if (!$this->criteriaSuccess[$key]) {
                $sumWeightFailureCriteria += $weight;
                $this->adjustedWeights[$key] = 0;
            } else {
                $this->adjustedWeights[$key] = $weight + ($sumWeightFailureCriteria/$criteriaSuccess);
            }
        }
    }

    public function scoring()
    {
        $this->weightAdjustment();

        $scoreOverall = 0;
        foreach ($this->criteriaSuccess as $key => $value) {
            if($this->scores[$key]) {
                $scoreOverall += ($this->scores[$key] * $this->adjustedWeights[$key]);
            }
        }

        return round($scoreOverall,2);
    }
}