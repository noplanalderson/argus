<?php
namespace App\Libraries;

use Dompdf\Dompdf;
use Dompdf\Options;

class FWDropReport
{
    private function quickChart(string $type, string $title, array $dataset, string $labelName = ''): string
    {
        $config = [
            'type' => $type,
            'data' => [
                'labels' => array_keys($dataset),
                'datasets' => [[
                    'data' => array_values($dataset)
                ]]
            ],
            'options' => [
                'title' => ['display' => true, 'text' => $title]
            ]
        ];
        if (!empty($labelName)) {
            $config['data']['datasets'][0]['label'] = $labelName;
        }
        $url = 'https://quickchart.io/chart?width=900&height=350&c='
            . urlencode(json_encode($config));

        return 'data:image/png;base64,' . base64_encode(file_get_contents($url));
    }

    /**
     * ===============================
     * GENERATE CHART IMAGE
     * ===============================
     */
    private function generateCharts(array $data): array
    {
        $countries = [];
        $isps = [];
        $ipCounts = [];
        $uniqueIps = [];
        $targets = [];

        foreach ($data as $row) {
            $country = $row['country'] ?? 'Unknown';
            $isp     = $row['isp'] ?? 'Unknown';
            $ip      = $row['ip_address'] ?? '';
            $agent   = $row['agent_name'] ?? 'Unknown';
            $count   = (int)($row['count'] ?? 1);

            $countries[$country] = ($countries[$country] ?? 0) + 1;
            $isps[$isp] = ($isps[$isp] ?? 0) + 1;
            $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + $count;
            $uniqueIps[$ip] = true;
            $targets[$agent] = ($targets[$agent] ?? 0) + 1;
        }

        arsort($countries);
        arsort($isps);
        arsort($ipCounts);
        arsort($targets);

        $topCountries = array_slice($countries, 0, 10, true);
        $topIsps      = array_slice($isps, 0, 10, true);
        $topTargets   = array_slice($targets, 0, 10, true);

        $topIp = array_key_first($ipCounts);
        $topIpCount = $ipCounts[$topIp] ?? 0;

        return [
            'countryChart' => $this->quickChart('bar', 'Top 10 Source Country', $topCountries, 'Country Name'),
            'ispChart'     => $this->quickChart('pie', 'Top 10 ISP', $topIsps),
            'targetChart'  => $this->quickChart('horizontalBar', 'Top 10 Target', $topTargets, 'Agent Name'),
            'totalIp'      => count($uniqueIps),
            'topIp'        => $topIp,
            'topIpCount'   => $topIpCount
        ];
    }



    /**
     * ===============================
     * BUILD HTML PDF
     * ===============================
     */
    private function buildHtml(array $data, array $charts): string
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
                
                .two-col {
                    display: table;
                    width: 100%;
                    table-layout: fixed;
                    margin-bottom: 5px;
                }

                .col {
                    display: table-cell;
                    width: 50%;
                    vertical-align: top;
                    padding: 5px;
                }

                .card {
                    background: #f8f9fa;
                    border-left: 4px solid #3498db;
                    padding: 15px;
                    border-radius: 6px;
                }

                .card h3 {
                    font-size: 12px;
                    margin-bottom: 8px;
                    color: #7f8c8d;
                    text-transform: uppercase;
                }

                .card .value {
                    font-size: 26px;
                    font-weight: bold;
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
                    margin-bottom: 5px;
                }
                
                .summary-box .value {
                    font-size: 32px;
                    font-weight: bold;
                    color: #2c3e50;
                }
                
                /* Chart Section */
                .chart-section {
                    margin: 5px 0;
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
                
                table thead {
                    background: #2c3e50;
                    color: white;
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
                    <h1>Wazuh FW Drop Report</h1>
                    <p style='margin-top: 10px;'>Period: {$period}</p>
                </div>
                <div class='two-col'>
                    <div class='col'>
                        <div class='card'>
                            <h3>Total Unique IP</h3>
                            <div class='value'>{$charts['totalIp']}</div>
                        </div>
                    </div>
                    <div class='col'>
                        <div class='card' style='border-left-color:#e74c3c'>
                            <h3>Top Attacker IP</h3>
                            <div class='value'>{$charts['topIp']}</div>
                            <div>Total Events: {$charts['topIpCount']}</div>
                        </div>
                    </div>
                </div>
                <!-- Chart Section -->
                <div class='two-col'>
                    <div class='col'>
                        <div class='chart-section'>
                            <div class='section-title'>Top 10 Source Country</div>
                            <img src='{$charts['countryChart']}'>
                        </div>
                    </div>
                    <div class='col'>
                        <div class='chart-section'>
                            <div class='section-title'>Top 10 ISP</div>
                            <img src='{$charts['ispChart']}'>
                        </div>
                    </div>
                </div>
                
                <div class='chart-section'>
                    <div class='section-title'>Top 10 Target</div>
                    <img src='{$charts['targetChart']}'>
                </div>

                <div class='page_break'></div>
                <!-- Detail Data Table -->
                <div class='table-section'>
                    <div class='section-title'>Detailed Analysis</div>
                    <table>
                        <thead>
                            <tr>
                                <th>Agent Name</th>
                                <th>Source IP</th>
                                <th>ISP / Provider</th>
                                <th>City</th>
                                <th>Country</th>
                                <th>Created At</th>
                                <th>Count</th>
                            </tr>
                        </thead>
                        <tbody>";
                
                foreach ($data as $d) {
                    
                    $html .= "
                            <tr>
                                <td><strong>{$d['agent_name']}</strong></td>
                                <td><strong>{$d['ip_address']}</strong></td>
                                <td>{$d['isp']}</td>
                                <td>{$d['city']}</td>
                                <td>{$d['country']}</td>
                                <td>{$d['created_at']}</td>
                                <td>{$d['count']}</td>
                            </tr>";
                }
                
                $html .= "
                        </tbody>
                    </table>
                </div>";
                
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
        $url = "{$_ENV['NEXTCLOUD_DAV']}/{$_ENV['NEXTCLOUD_DIR2']}/$filename";

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
        $dir  = trim($_ENV['NEXTCLOUD_DIR2'], '/');
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
        $filename = 'Wazuh-FWdrop-report-' . date('Ymd-His') . '.pdf';

        $charts = $this->generateCharts($data);
        $html = $this->buildHtml($data, $charts);
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
            'share_link' => $share
        ];
    }
}
