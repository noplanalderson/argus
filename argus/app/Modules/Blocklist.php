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

    public function __construct($dateStart, $dateEnd, $limit, $offset)
    {
        $this->dateStart = $dateStart;
        $this->dateEnd = $dateEnd;
        $this->limit = abs($limit);
        $this->offset = abs($offset);
    }

    public function getBlocklist()
    {
        $result = [
            'already_analyzed' => false,
            'blockmode' => false 
        ];

        $results = DB::from('tb_ip_address', 'a')
                        ->select([
                            'a.ip_address',
                            'a.isp',
                            'a.location',
                            "JSON_UNQUOTE(JSON_EXTRACT(b.decision, '$.blockmode')) AS blockmode",
                            'b.created_at'
                        ])
                        ->join('tb_analysis_history AS b', 'a.ip_id_uuid = b.ip_id_uuid')
                        ->whereRaw('DATE(b.created_at) >= :start', [':start' => $this->dateStart])
                        ->whereRaw('DATE(b.created_at) <= :end', [':end' => $this->dateEnd])
                        ->orderBy('a.created_at', 'desc')
                        ->limit($this->limit, $this->offset)
                        ->get();
            
        return $results;
    }
}