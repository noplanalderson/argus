<?php
namespace App\Libraries;

use Dompdf\Dompdf;
use Dompdf\Options;

class NextcloudReport
{
    /**
     * ===============================
     * SUMMARY CALCULATION
     * ===============================
     */
    private function buildSummary(array $data): array
    {
        $openAi = new OpenAISummary();
        $aiSummary = $openAi->summary($data);
        // $aiSummary = "<p><strong>Summary:</strong> Database berisi 106 entri IP yang dimasukkan ke blocklist. Mayoritas entri diberi 
        //             bajakan blok 7d, ada satu entri dengan status permanent. Sebagian besar basal dari penyedia cloud (Microsoft, 
        //             DigitalOcean, Amazon) dan beberapa ISP nasional (beberapa asal Indonesia). Skor gabungan overall_score 
        //             menunjukkan sebagian besar entri berada di rentang menengah mengecil (<50 Score) dan beberapa 
        //             outlier berisiko tinggi (> 55).</p>
        //         <br>
        //         <p><strong>Key Findings:</strong></p>
        //         <ul style='margin-left: 20px; margin-top: 10px;'>
        //             <li>Critical entries detected: 5 IPs dengan score di atas 70 (high risk)</li>
        //             <li>Predominant threat sources: DigitalOcean dan Microsoft Cloud</li>
        //             <li>Geographic distribution: Asia-Pacific region mendominasi dengan 73% dari total entries</li>
        //             <li>Block duration: 7 hari adalah durasi block yang paling umum (94% dari entries)</li>
        //             <li>Trend: Aktivitas mencurigakan menunjukkan peningkatan pada 11-12 February 2026</li>
        //         </ul>";
        $total = count($data);
        $highRisk = 0;
        $totalScore = 0;

        foreach ($data as $d) {
            $totalScore += $d['overall_score'];
            if ($d['overall_score'] >= 70) {
                $highRisk++;
            }
        }

        return [
            'total' => $total,
            'highRisk' => $highRisk,
            'avgScore' => round($totalScore / max($total,1), 2),
            'ai_summary' => $aiSummary
        ];
    }

    /**
     * ===============================
     * GENERATE CHART IMAGE
     * ===============================
     */
    private function generateChart(array $data): string
    {
        $countries = [];

        foreach ($data as $row) {
            // Explode: Negara - Kota
            $parts = explode(' - ', $row['location']);
            $country = trim($parts[0]);

            if (!isset($countries[$country])) {
                $countries[$country] = 0;
            }

            $countries[$country]++;
        }

        $labels = array_keys($countries);
        $values = array_values($countries);

        $config = [
            'type' => 'bar',
            'data' => [
                'labels' => $labels,
                'datasets' => [[
                    'label' => 'Source Country',
                    'data' => $values,
                    'backgroundColor' => 'rgba(54, 162, 235, 0.7)'
                ]]
            ],
            "options" => [
                "responsive" => true,
                "title" => [
                    "display" => true,
                    "text" => "Attackers per Country"
                ],
                "scales" => [
                    "xAxes" => [
                        "gridLines" => [
                            "display" => true
                        ]
                    ],
                    "yAxes" => [
                        "gridLines" => [
                            "display" => true
                        ],
                        "min" => 0,
                        "ticks" => [
                            "stepSize" => 5
                        ]
                    ]
                ]
            ]
        ];

        $url = 'https://quickchart.io/chart?width=900&height=350&c='
            . urlencode(json_encode($config));

        $image = file_get_contents($url);

        return 'data:image/png;base64,' . base64_encode($image);
    }

    /**
     * ===============================
     * BUILD HTML PDF
     * ===============================
     */
    private function buildHtml(array $data, array $summary, string $chartPath): string
    {
        $period = date('d M Y H:i', strtotime('-24 hours')) . ' - ' . date('d M Y H:i');
        
        $html = "
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset='UTF-8'>
            <meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: 'Segoe UI Emoji', 'Apple Color Emoji', Tahoma, Geneva, Verdana, sans-serif;
                    font-size: 11px;
                    color: #333;
                    line-height: 1.6;
                    background: #f5f5f5;
                    padding: 20px;
                }
                
                .container {
                    width: 100%;
                    max-width: none;
                    box-shadow: none;
                }
                
                /* Header */
                .header {
                    text-align: center;
                    border-bottom: 3px solid #2c3e50;
                    padding-bottom: 20px;
                    margin-bottom: 20px;
                }
                
                .header h1 {
                    font-size: 28px;
                    color: #2c3e50;
                    font-weight: bold;
                    margin-bottom: 5px;
                }
                
                .header p {
                    font-size: 12px;
                    color: #7f8c8d;
                }
                
                /* Summary Section */
                .summary-section {
                    display: table;
                    width: 100%;
                    table-layout: fixed;
                    margin: 20px 0 10px 0;
                    page-break-inside: avoid;
                }

                .summary-box {
                    display: table-cell;
                    width: 33.33%;
                    padding: 15px;
                    border-radius: 8px;
                    border-left: 4px solid;
                    background: #f8f9fa;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
                }
                
                .summary-box.total {
                    border-left-color: #3498db;
                }
                
                .summary-box.high-risk {
                    border-left-color: #e74c3c;
                    background: #fdeaea;
                }
                
                .summary-box.average {
                    border-left-color: #f39c12;
                }
                
                .summary-box label {
                    display: block;
                    font-size: 12px;
                    color: #7f8c8d;
                    font-weight: 600;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    margin-bottom: 8px;
                }
                
                .summary-box .value {
                    font-size: 32px;
                    font-weight: bold;
                    color: #2c3e50;
                }
                
                /* Chart Section */
                .chart-section {
                    margin: 30px 0;
                    padding: 20px;
                    background: #f8f9fa;
                    border-radius: 8px;
                    page-break-inside: avoid;
                }
                
                .section-title {
                    font-size: 16px;
                    font-weight: bold;
                    color: #2c3e50;
                    margin-bottom: 15px;
                    border-left: 4px solid #3498db;
                    padding-left: 10px;
                }
                
                .chart-section img {
                    width: 100%;
                    max-height: 350px;
                    border-radius: 6px;
                }
                
                /* Table */
                .table-section {
                    margin: 30px 0;
                }
                
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                    background: white;
                    border-radius: 6px;
                    overflow: hidden;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
                }
                
                table thead th {
                    background: #2c3e50 !important;
                    color: white !important;
                }
                
                table th {
                    padding: 12px;
                    text-align: left;
                    font-weight: 600;
                    font-size: 11px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                
                table td {
                    padding: 10px 12px;
                    border-bottom: 1px solid #ecf0f1;
                    font-size: 10px;
                }
                
                table tbody tr {
                    transition: background 0.2s;
                }
                
                table tbody tr:hover {
                    background: #f8f9fa;
                }
                
                /* Score coloring */
                .score-critical {
                    background: #ffcccc;
                    color: #c0392b;
                    font-weight: bold;
                    padding: 2px 6px;
                    border-radius: 3px;
                }
                
                .score-high {
                    background: #fff3cd;
                    color: #856404;
                    padding: 2px 6px;
                    border-radius: 3px;
                }
                
                .score-medium {
                    background: #d4edda;
                    color: #155724;
                    padding: 2px 6px;
                    border-radius: 3px;
                }
                
                .score-low {
                    background: #d1ecf1;
                    color: #0c5460;
                    padding: 2px 6px;
                    border-radius: 3px;
                }
                
                /* AI Summary */
                .ai-summary-section {
                    margin: 30px 0;
                    padding: 20px;
                    background: #ecf0f1;
                    border-left: 4px solid #9b59b6;
                    border-radius: 6px;
                }
                
                .ai-summary-section .section-title {
                    border-left-color: #9b59b6;
                    margin-bottom: 15px;
                }
                
                .ai-summary-text {
                    font-size: 11px;
                    line-height: 1.7;
                    color: #2c3e50;
                }
                
                /* Footer */
                .footer {
                    margin-top: 40px;
                    padding-top: 15px;
                    border-top: 1px solid #ecf0f1;
                    text-align: center;
                    font-size: 9px;
                    color: #95a5a6;
                }
                
                /* Responsive */
                @media (max-width: 768px) {
                    .summary-section {
                        flex-direction: column;
                    }
                    
                    .summary-box {
                        min-width: 100%;
                    }
                }
                .page_break { page-break-before: always; }
            </style>
        </head>
        <body>
            <div class='container'>
                <!-- Header -->
                <div class='header'>
                    <h1>Argus-OSINT Report</h1>
                    <p>Network Security Intelligence Dashboard</p>
                    <p style='margin-top: 10px;'>Period: {$period}</p>
                </div>
                
                <!-- Summary Boxes -->
                <div class='summary-section'>
                    <div class='summary-box total'>
                        <label>Total IP Addresses</label>
                        <div class='value'>{$summary['total']}</div>
                    </div>
                    <div class='summary-box high-risk'>
                        <label>High Risk (Score >= 70)</label>
                        <div class='value'>{$summary['highRisk']}</div>
                    </div>
                    <div class='summary-box average'>
                        <label>Average Risk Score</label>
                        <div class='value'>{$summary['avgScore']}</div>
                    </div>
                </div>
                
                <!-- Chart Section -->
                <div class='chart-section'>
                    <div class='section-title'>Score Distribution</div>
                    <img src='{$chartPath}' alt='Score Distribution Chart'>
                </div>
                <div class='page_break'></div>
                <!-- Detail Data Table -->
                <div class='table-section'>
                    <div class='section-title'>Detailed Analysis</div>
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>ISP / Provider</th>
                                <th>Location</th>
                                <th>Block</th>
                                <th>Wazuh</th>
                                <th>TIP</th>
                                <th>Overall Score</th>
                                <th>Created</th>
                                <th>Updated</th>
                            </tr>
                        </thead>
                        <tbody>";
                
                foreach ($data as $d) {
                    $overall = (int)$d['overall_score'];
                    
                    if ($overall >= 70) {
                        $scoreClass = 'score-critical';
                    } elseif ($overall >= 40) {
                        $scoreClass = 'score-high';
                    } elseif ($overall >= 20) {
                        $scoreClass = 'score-medium';
                    } else {
                        $scoreClass = 'score-low';
                    }
                    
                    $html .= "
                            <tr>
                                <td><strong>{$d['ip_address']}</strong></td>
                                <td>{$d['isp']}</td>
                                <td>{$d['location']}</td>
                                <td>{$d['blockmode']}</td>
                                <td>" . round($d['wazuh_score'], 1) . "</td>
                                <td>" . round($d['tip_score'], 1) . "</td>
                                <td><span class='{$scoreClass}'>" . round($d['overall_score'], 1) . "</span></td>
                                <td>{$d['created_at']}</td>
                                <td>{$d['updated_at']}</td>
                            </tr>";
                }
                
                $html .= "
                        </tbody>
                    </table>
                </div>
                <div class='page_break'></div>";
                
                // AI Summary Section
                if (!empty($summary['ai_summary'])) {
                    $openAiSummary = $summary['ai_summary'];
                    $html .= "
                    <div class='ai-summary-section'>
                        <div class='section-title'>AI-Powered Insights</div>
                        <div class='ai-summary-text'>
                            {$openAiSummary}
                        </div>
                    </div>";
                }
                
                // Footer
                $html .= "
                <div class='footer'>
                    <p>Generated: " . date('d M Y H:i:s') . " | Argus Security Intelligence System</p>
                </div>
                
            </div>
        </body>
        </html>";
                
        return $html;
    }

    /**
     * ===============================
     * GENERATE PDF
     * ===============================
     */
    private function createPdf(string $html, string $filename): string
    {
        $options = new Options();
        $options->set('isRemoteEnabled', true);
        $options->set('defaultFont', 'Helvetica');
        $options->set('chroot', [
            __DIR__,
            sys_get_temp_dir(),
            '/tmp',
        ]);
        
        $pdf = new Dompdf($options);
        // Menambahkan UTF-8 encoding pada HTML header
        $html = '<?xml version="1.0" encoding="UTF-8"?>' . $html;
        $pdf->loadHtml($html, 'UTF-8');
        $pdf->setPaper('A4', 'landscape');
        $pdf->render();
        
        $temp = sys_get_temp_dir() . '/' . $filename;
        file_put_contents($temp, $pdf->output());
        
        return $temp;
    }

    /**
     * ===============================
     * UPLOAD FILE
     * ===============================
     */
    private function uploadToNextcloud(string $tempFile, string $filename): int
    {
        $url = "{$_ENV['NEXTCLOUD_DAV']}/{$_ENV['NEXTCLOUD_DIR']}/$filename";

        $fp = fopen($tempFile, 'r');

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_USERPWD, $_ENV['NEXTCLOUD_USER'] . ':' . $_ENV['NEXTCLOUD_PWD']);
        curl_setopt($ch, CURLOPT_PUT, true);
        curl_setopt($ch, CURLOPT_INFILE, $fp);
        curl_setopt($ch, CURLOPT_INFILESIZE, filesize($tempFile));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        curl_close($ch);
        fclose($fp);

        return $httpCode;
    }

    /**
     * ===============================
     * CREATE SHARE LINK
     * ===============================
     */
    private function createShareLink(string $filename)
    {
        $dir  = trim($_ENV['NEXTCLOUD_DIR'], '/');
        $path = '/' . $dir . '/' . $filename;

        $ch = curl_init(
            rtrim($_ENV['NEXTCLOUD_BASE'], '/') .
            '/ocs/v2.php/apps/files_sharing/api/v1/shares'
        );

        curl_setopt_array($ch, [
            CURLOPT_USERPWD => $_ENV['NEXTCLOUD_USER'] . ':' . $_ENV['NEXTCLOUD_PWD'],
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => [
                'OCS-APIRequest: true',
                'Accept: application/xml'
            ],
            CURLOPT_POSTFIELDS => http_build_query([
                'path' => $path,
                'shareType' => 3,
                'permissions' => 1
            ]),
            CURLOPT_RETURNTRANSFER => true
        ]);

        $response = curl_exec($ch);
        curl_close($ch);
        $response = html_entity_decode($response, ENT_QUOTES);

        $xml = simplexml_load_string($response, 'SimpleXMLElement', LIBXML_NOCDATA);

        if ($xml === false) {
            return null;
        }

        $url = (string) $xml->data->url;

        return $url ?: null;
    }

    /**
     * ===============================
     * PUBLIC GENERATOR
     * ===============================
     */
    public function generate(array $data): array
    {
        $filename = 'Argus-report-' . date('Ymd-His') . '.pdf';

        $summary = $this->buildSummary($data);
        $chart = $this->generateChart($data);
        $html = $this->buildHtml($data, $summary, $chart);
        $pdfFile = $this->createPdf($html, $filename);

        if (empty($_ENV['NEXTCLOUD_BASE']) || empty($_ENV['NEXTCLOUD_USER'])) {
            // Download file instead
            header('Content-Type: application/pdf');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            readfile($pdfFile);
            unlink($pdfFile);
            exit;
        }

        $status = $this->uploadToNextcloud($pdfFile, $filename);
        $share = $this->createShareLink($filename);

        unlink($pdfFile);
        

        return [
            'status' => $status == 201 || $status == 204 ? 'success' : 'error',
            // 'status' => 'success',
            'ai_summary' => $summary['ai_summary'],
            'share_link' => $share
        ];
    }
}
