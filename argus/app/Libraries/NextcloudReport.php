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
            'avgScore' => round($totalScore / max($total,1), 2)
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
        <style>
        body { font-family: DejaVu Sans; font-size: 10px; }
        h1,h2 { text-align:center; }

        .summary { display:flex; justify-content:space-around; margin-bottom:15px; }
        .box { border:1px solid #333; padding:10px; width:30%; text-align:center; }
        .high { background:#ffcccc; }

        table { width:100%; border-collapse:collapse; margin-top:15px; }
        th, td { border:1px solid #333; padding:5px; }
        th { background:#eee; }

        .score-high { background:#ff9999; font-weight:bold; }
        .score-medium { background:#fff3cd; }
        </style>

        <h1>Argus-OSINT Report</h1>
        <p>Period: {$period}</p>

        <div class='summary'>
            <div class='box'>Total IP<br><b>{$summary['total']}</b></div>
            <div class='box high'>High Risk<br><b>{$summary['highRisk']}</b></div>
            <div class='box'>Average Score<br><b>{$summary['avgScore']}</b></div>
        </div>

        <h2>Score Distribution</h2>
        <img src='{$chartPath}' width='100%'>

        <h2>Detail Data</h2>
        <table>
        <tr>
        <th>IP</th>
        <th>ISP</th>
        <th>Location</th>
        <th>Block</th>
        <th>Wazuh</th>
        <th>TIP</th>
        <th>Overall</th>
        <th>Created</th>
        <th>Updated</th>
        </tr>
        ";

        foreach ($data as $d) {

            $class = $d['overall_score'] >= 70 ? 'score-high'
                    : ($d['overall_score'] >= 40 ? 'score-medium' : '');

            $html .= "
            <tr class='$class'>
                <td>{$d['ip_address']}</td>
                <td>{$d['isp']}</td>
                <td>{$d['location']}</td>
                <td>{$d['blockmode']}</td>
                <td>{$d['wazuh_score']}</td>
                <td>{$d['tip_score']}</td>
                <td>{$d['overall_score']}</td>
                <td>{$d['created_at']}</td>
                <td>{$d['updated_at']}</td>
            </tr>";
        }

        return $html . "</table>";
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

        $pdf = new Dompdf($options);
        $pdf->loadHtml($html);
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

        $status = $this->uploadToNextcloud($pdfFile, $filename);
        $share = $this->createShareLink($filename);

        unlink($pdfFile);
        

        return [
            'status' => $status == 201 || $status == 204 ? 'success' : 'error',
            'share_link' => $share
        ];
    }
}
