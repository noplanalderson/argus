<?php
namespace App\Modules;
use App\Config\Database;
class CheckIP
{
    protected $ip;

    public function __construct($ip)
    {
        $this->ip = $ip;
    }

    public function check()
    {
        $result = [
            'already_analyzed' => false,
            'blockmode' => false 
        ];

        $db = (new Database())->getConnection();
        $stmt = $db->prepare("
            SELECT `a`.`history_id_uuid`, `b`.`ip_id_uuid`, `b`.`ip_address`, `a`.`overall_score`, `a`.`decision`, `a`.`created_at`
            FROM `tb_analysis_history` `a`
            INNER JOIN `tb_ip_address` `b` ON `a`.`ip_id_uuid` = `b`.`ip_id_uuid`
            WHERE `b`.`ip_address` = ?
            ORDER BY `a`.`created_at` DESC
            LIMIT 1
        ");
        $stmt->execute([$this->ip]);
        $history = $stmt->fetch();

        if ($history && isset($history['decision'])) {
            $history['decision'] = json_decode($history['decision'], true);

            if($history['decision']['blockmode'] !== false) {
                $result = [
                    'already_analyzed' => true,
                    'blockmode' => $history['decision']['blockmode']
                ];
            }
        }

        return $result;
    }
}