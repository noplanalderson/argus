<?php
namespace App\Modules;
use App\Config\Database;
use App\Cores\DB;
/**
 * Blocklist Class
 * Get IP blocklists with date range
 * 
 * @package Argus Service
 * @author  Muhammad Ridwan Na'im <ridwannaim@tangerangkota.go.id>
 * @since 2025
 * @version 2.0.0
*/
class Blocklist
{
    protected $dateStart;
    protected $dateEnd;
    protected $limit = 10;
    protected $offset = 0;

    public function __construct($dateStart = null, $dateEnd = null, $limit = 0, $offset = 0)
    {
        $this->dateStart = $dateStart;
        $this->dateEnd = $dateEnd;
        $this->limit = abs($limit);
        $this->offset = abs($offset);
    }

    public function getBlocklist()
    {
        $results = DB::from('tb_ip_address', 'a')
                        ->select([
                            'a.ip_address',
                            'a.isp',
                            'a.location',
                            "JSON_UNQUOTE(JSON_EXTRACT(b.decision, '$.blockmode')) AS blockmode",
                            'b.created_at',
                            'b.updated_at',
                            'b.wazuh_score',
                            'b.tip_score',
                            'b.overall_score'
                        ])
                        ->join('tb_analysis_history AS b', 'a.ip_id_uuid = b.ip_id_uuid')
                        ->whereRaw('b.created_at >= :start', [':start' => $this->dateStart])
                        ->whereRaw('b.created_at <= :end', [':end' => $this->dateEnd])
                        ->orderBy('b.created_at', 'desc')
                        ->limit($this->limit, $this->offset)
                        ->get();
            
        return $results;
    }

    public function getBlocklist24h()
    {
        $results = DB::from('tb_ip_address', 'a')
                        ->select([
                            'a.ip_address',
                            'a.isp',
                            'a.location',
                            'a.country_code',
                            "JSON_UNQUOTE(JSON_EXTRACT(b.decision, '$.blockmode')) AS blockmode",
                            'b.created_at',
                            'b.updated_at',
                            'b.wazuh_score',
                            'b.tip_score',
                            'b.overall_score'
                        ])
                        ->join('tb_analysis_history AS b', 'a.ip_id_uuid = b.ip_id_uuid')
                        ->whereRaw("b.created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) OR b.updated_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)")
                        ->orderBy('b.created_at', 'desc')
                        ->get();
            
        return $results;
    }

    public function getBlocklistFWDrop()
    {
        $results = DB::from('firewall_drop', 'b')
                        ->select([
                            'b.ip_address',
                            'b.isp',
                            'b.country',
                            'b.city',
                            'a.created_at',
                            'a.agent_name',
                            'a.count',
                        ])
                        ->join('fw_drop_event AS a', 'b._id = a.source_ip_id')
                        ->whereRaw("a.created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)")
                        ->orderBy('a.created_at', 'desc')
                        ->orderBy('a.count', 'desc')
                        ->get();
            
        return $results;
    }
}