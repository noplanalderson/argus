<?php
namespace App\Modules;
use App\Config\Database;
use App\Cores\DB;
/**
 * Jobs Class
 * Get Jobs with date range
 * 
 * @package Argus Service
 * @author  Muhammad Ridwan Na'im <ridwannaim@tangerangkota.go.id>
 * @since 2025
 * @version 2.0.0
*/
class Jobs
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

    public function getJobs()
    {
        $results = DB::from('tb_jobs')
                        ->select(['observable', 'created_at', 'CAST(JSON_UNQUOTE(results) AS JSON) AS results'])
                        ->whereRaw('DATE(created_at) >= :start', [':start' => $this->dateStart])
                        ->whereRaw('DATE(created_at) <= :end', [':end' => $this->dateEnd])
                        ->orderBy('created_at', 'desc')
                        ->limit($this->limit, $this->offset)
                        ->get();
            
        return $results;
    }
}