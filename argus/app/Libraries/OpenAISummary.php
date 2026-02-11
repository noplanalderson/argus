<?php
namespace App\Libraries;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

class OpenAISummary
{
    protected $client;

    protected $apiKey;

    public function __construct()
    {
        $this->client = new Client([
            'timeout' => 120,
        ]);
    }

    public function summary($data)
    {
        $blocklistJson = json_encode($data, JSON_PRETTY_PRINT);

        $prompt = "
        Analisis data blocklist berikut (format JSON) dan buatkan secara singkat laporan dengan struktur:

        1. Executive Summary
        2. Technical Insight (negara, ISP, skor)
        3. Risk Assessment
        4. Rekomendasi tindakan SOC

        Data:
        $blocklistJson
        ";

        try {

            $response = $this->client->post('https://api.openai.com/v1/responses', [
                'headers' => [
                    'Authorization' => 'Bearer ' . $_ENV['OPENAI_KEY'],
                    'OpenAI-Organization' => $_ENV['OPENAI_ORG'],
                    'OpenAI-Project' => $_ENV['OPENAI_PROJ'],
                    'Content-Type'  => 'application/json',
                ],
                'json' => [
                    'model' => 'gpt-5-mini',
                    'input' => [
                        [
                            'role' => 'system',
                            'content' => 'Anda adalah SOC Analyst senior di lingkungan pemerintahan.'
                        ],
                        [
                            'role' => 'user',
                            'content' => $prompt
                        ]
                    ]
                ]
            ]);

            $data = json_decode($response->getBody(), true);

            $summary = $data['output'][1]['content'][0]['text'] ?? 'No summary available.';

            return $summary;

        } catch (RequestException $e) {

            return "OpenAI API Error: ".$e->getMessage();

        }
    }
}