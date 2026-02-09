<?php
namespace App\Libraries;

/**
 * CriminalIP Scoring Calculator
 */
class ThreatbookScoring
{
    private $weights;

    private $judgementWeights = [
        'C2' => 25,           // Command and Control - sangat berbahaya
        'Botnet' => 20,       // Node dalam botnet
        'Hijacked' => 18,     // Sistem yang diambil alih
        'Phishing' => 22,     // Situs phishing
        'Malware' => 20,      // Distribusi malware
        'Exploit' => 15,      // Eksploitasi vulnerability
        'Scanner' => 12,      // Network scanning
        'Zombie' => 18,       // Bot yang dikendalikan attacker
        'Spam' => 10,         // Distribusi spam
        'Compromised' => 15,  // Host yang terinfiltrasi
        'Brute Force' => 16,  // Serangan brute force
        'Tor' => 8,           // Tor exit node (dari data)
        'Dynamic IP' => 5,    // IP dinamis (risiko rendah),
        'VPN' => 10,
        'DDNS' => 10
    ];
    
    private $highRiskCountry = [
        'CN', 'RU', 'KP', 'IR', 'SY', 'VE', 'CU', 'SD', 'TH', 'AS', 'KH', 'IN', 'BD', 'RO'
    ];

    private $data = [];

    public function __construct(array $data)
    {   
        // Sample data
        // {
        //     "data": {
        //         "summary": {
        //             "judgments": [
        //                 "Zombie",
        //                 "Tor",
        //                 "Spam"
        //             ],
        //             "whitelist": false,
        //             "first_seen": "2023-03-13",
        //             "last_seen": "2026-02-09"
        //         },
        //         "basic": {
        //             "carrier": "Foundation for Applied Privacy",
        //             "location": {
        //                 "country": "Austria",
        //                 "province": "Wien",
        //                 "city": "Vienna",
        //                 "lng": "16.367217",
        //                 "lat": "48.203183",
        //                 "country_code": "AT"
        //             }
        //         },
        //         "asn": {
        //             "rank": 4,
        //             "info": "APPLIEDPRIVACY-AS, AT",
        //             "number": 208323
        //         },
        //         "ports": [],
        //         "cas": [],
        //         "IP": "109.70.100.10"
        //     },
        //     "response_code": 200,
        //     "msg": "Success"
        // }
        $this->data = $data;
    }

    public function calculateScore(): float
    {
        $score = 0.0;

        // Cek judgement
        if (isset($this->data['data']['summary']['judgments']) && is_array($this->data['data']['summary']['judgments'])) {
            foreach ($this->data['data']['summary']['judgments'] as $judgement) {
                if (isset($this->judgementWeights[$judgement])) {
                    $score += $this->judgementWeights[$judgement];
                }
            }
        }

        // Cek country
        $countryCode = $this->data['data']['basic']['location']['country_code'] ?? '';
        if (in_array($countryCode, $this->highRiskCountry)) {
            $score += 15; // Tambah skor jika dari negara berisiko tinggi
        }

        // Normalisasi skor ke skala 0-100
        if ($score > 100) {
            $score = 100;
        }

        return round($score, 2);
    }
}