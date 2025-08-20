<?php
namespace App\Libraries;

/**
 * CriminalIP Scoring Calculator
 */
class CriminalIPScoring
{
    private $weights;

    public function __construct()
    {
        // Bobot disesuaikan agar total = 1.0 (normalized)
        $this->weights = [
            'ip_inbound'        => 0.23, // max 30
            'ip_outbound'       => 0.15, // max 20
            'is_malicious'      => 0.15, // max 20
            'open_ports'        => 0.08, // max 10
            'port_vulnerability'=> 0.15, // max 20
            'vulnerabilities'   => 0.12, // max 15
            'exploit_db'        => 0.08, // max 10
            'policy_violation'  => 0.04  // max 5
        ];
    }

    /**
     * Hitung skor berdasarkan data JSON CriminalIP
     */
    public function calculateScore(array $data): array
    {
        $score = 0.0;

        // --- ip_scoring inbound ---
        $mapInbound = ['Critical'=>1.0,'High'=>0.67,'Moderate'=>0.33,'Low'=>0.17];
        $inbound = $data['ip_scoring']['inbound'] ?? 'Low';
        $score += ($mapInbound[$inbound] ?? 0) * $this->weights['ip_inbound'];

        // --- ip_scoring outbound ---
        $mapOutbound = ['Critical'=>1.0,'High'=>0.75,'Moderate'=>0.5,'Low'=>0.25];
        $outbound = $data['ip_scoring']['outbound'] ?? 'Low';
        $score += ($mapOutbound[$outbound] ?? 0) * $this->weights['ip_outbound'];

        // --- malicious flag ---
        if (!empty($data['ip_scoring']['is_malicious'])) {
            $score += 1.0 * $this->weights['is_malicious'];
        }

        // --- jumlah open ports ---
        $ports = count($data['current_open_ports']['TCP'] ?? []);
        if ($ports > 10) {
            $score += 1.0 * $this->weights['open_ports'];
        } elseif ($ports >= 5) {
            $score += 0.5 * $this->weights['open_ports'];
        } else {
            $score += 0.2 * $this->weights['open_ports'];
        }

        // --- ada port vulnerable? ---
        $hasVulnPort = false;
        foreach ($data['current_open_ports']['TCP'] as $port) {
            if ($port['has_vulnerability']) {
                $hasVulnPort = true;
                break;
            }
        }
        if ($hasVulnPort) {
            $score += 1.0 * $this->weights['port_vulnerability'];
        }

        // --- vulnerabilities ---
        $vuln = $data['summary']['security']['vulnerabilities'] ?? 0;
        if ($vuln > 10) {
            $score += 1.0 * $this->weights['vulnerabilities'];
        } elseif ($vuln > 5) {
            $score += 0.67 * $this->weights['vulnerabilities'];
        } elseif ($vuln > 0) {
            $score += 0.33 * $this->weights['vulnerabilities'];
        }

        // --- exploit db ---
        $exploit = $data['summary']['security']['exploit_db'] ?? 0;
        if ($exploit > 2) {
            $score += 1.0 * $this->weights['exploit_db'];
        } elseif ($exploit > 0) {
            $score += 0.5 * $this->weights['exploit_db'];
        }

        // --- policy violation ---
        if (($data['summary']['security']['policy_violation'] ?? 0) > 0) {
            $score += 1.0 * $this->weights['policy_violation'];
        }

        // Normalisasi ke skala 0 - 100
        $normalized = round($score * 100, 2);

        // Level risk
        $level = 'Low';
        if ($normalized >= 81) {
            $level = 'Critical';
        } elseif ($normalized >= 61) {
            $level = 'High';
        } elseif ($normalized >= 31) {
            $level = 'Medium';
        }

        return [
            'score' => $normalized,
            'level' => $level
        ];
    }
}
