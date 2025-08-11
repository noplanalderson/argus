<?php
namespace App\Cores;

class Response
{
    /**
     * Outputs data as JSON and sets appropriate headers.
     *
     * @param mixed $data The data to be encoded as JSON.
     * @param int $statusCode HTTP status code to send with the response (default: 200).
     */
    public function setJSON($data, $statusCode = 200) {
        header('Content-Type: application/json');
        http_response_code($statusCode);
        echo json_encode($data);
        exit;
    }
}