<?php
require_once __DIR__ . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$db_host = $_ENV['DB_HOST'];
$db_user = $_ENV['DB_USER'];
$db_pass = $_ENV['DB_PASS'];
$db_name = $_ENV['DB_NAME'];

function connectDB() {
    global $db_host, $db_user, $db_pass, $db_name;
    $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    return $conn;
}

function mapVirusTotalScore($category) {
    $category = strtolower($category);
    switch ($category) {
        case 'clean':
            return 0;
        case 'suspicious':
            return 50;
        case 'malicious':
            return 100;
        default:
            return 0;
    }
}

function getReliabilityWeights($conn, $ip_id_uuid) {
    $weights = ['abuseipdb' => 1/3, 'virustotal' => 1/3, 'crowdsec' => 1/3];
    $stmt = $conn->prepare("SELECT ip_id_uuid, classification FROM tb_ip_address WHERE ip_id_uuid = ?");
    $stmt->bind_param("s", $ip_id_uuid);
    $stmt->execute();
    $result = $stmt->get_result();
    $reliability = [];
    if ($row = $result->fetch_assoc()) {
        $classification = json_decode($row['classification'], true);
        if (is_array($classification)) {
            foreach ($classification as $platform => $score) {
                $reliability[$platform] = $score > 0 ? 1 : 0; // Simplified reliability based on past scores
            }
        }
    }
    $stmt->close();

    $total_accuracy = array_sum($reliability);
    if ($total_accuracy > 0) {
        foreach ($reliability as $platform => $accuracy) {
            $weights[$platform] = $accuracy / $total_accuracy;
        }
    }
    
    return $weights;
}

function getRecurrencePenalty($conn, $ip_id_uuid) {
    $penalty = 0;
    $stmt = $conn->prepare("SELECT COUNT(*) as count FROM tb_analysis_history WHERE ip_id_uuid = ? AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)");
    $stmt->bind_param("s", $ip_id_uuid);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    if ($row['count'] > 0) {
        $penalty = 10;
    }
    $stmt->close();
    return $penalty;
}

function calculateThreatScore($abuseipdb_score, $virustotal_category, $crowdsec_score, $ip_id_uuid) {
    $conn = connectDB();
    $virustotal_score = mapVirusTotalScore($virustotal_category);
    $weights = getReliabilityWeights($conn, $ip_id_uuid);
    $saw_score = ($weights['abuseipdb'] * $abuseipdb_score + $weights['virustotal'] * $virustotal_score + $weights['crowdsec'] * $crowdsec_score);
    $penalty = getRecurrencePenalty($conn, $ip_id_uuid);
    $final_score = $saw_score + $penalty;

    $action = '';
    if ($final_score < 30) {
        $action = 'No action';
    } elseif ($final_score >= 30 && $final_score <= 49) {
        $action = '3-day block';
    } elseif ($final_score >= 50 && $final_score <= 69) {
        $action = '7-day block';
    } else {
        $action = 'Permanent block';
    }

    $decision = json_encode(['action' => $action, 'score' => $final_score]);
    $stmt = $conn->prepare("INSERT INTO tb_analysis_history (history_id_uuid, ip_id_uuid, crowdsec_score, vt_score, abuseip_score, overall_score, decision, created_at) VALUES (UUID(), ?, ?, ?, ?, ?, NOW())");
    $stmt->bind_param("sdddds", $ip_id_uuid, $crowdsec_score, $virustotal_score, $abuseipdb_score, $final_score, $decision);
    $stmt->execute();
    $stmt->close();

    $conn->close();

    return [
        'ip_id_uuid' => $ip_id_uuid,
        'abuseipdb_score' => $abuseipdb_score,
        'virustotal_score' => $virustotal_score,
        'crowdsec_score' => $crowdsec_score,
        'weights' => $weights,
        'saw_score' => $saw_score,
        'penalty' => $penalty,
        'final_score' => $final_score,
        'action' => $action
    ];
}

$ip_id_uuid = '550e8400-e29b-41d4-a716-446655440000'; // Example UUID
$abuseipdb_score = 80;
$virustotal_category = 'clean';
$crowdsec_score = 60;

$result = calculateThreatScore($abuseipdb_score, $virustotal_category, $crowdsec_score, $ip_id_uuid);

echo "<pre>";
echo "IP ID UUID: " . $result['ip_id_uuid'] . "\n";
echo "AbuseIPDB Score: " . $result['abuseipdb_score'] . "\n";
echo "VirusTotal Score: " . $result['virustotal_score'] . "\n";
echo "Crowdsec Score: " . $result['crowdsec_score'] . "\n";
echo "Weights: " . json_encode($result['weights'], JSON_PRETTY_PRINT) . "\n";
echo "SAW Score: " . number_format($result['saw_score'], 2) . "\n";
echo "Recurrence Penalty: " . $result['penalty'] . "\n";
echo "Final Score: " . number_format($result['final_score'], 2) . "\n";
echo "Action: " . $result['action'] . "\n";
echo "</pre>";
?>