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
                        ->select(['observable', 'created_at', 'JSON_UNQUOTE(results) AS results'])
                        ->whereRaw('DATE(created_at) >= :start', [':start' => $this->dateStart])
                        ->whereRaw('DATE(created_at) <= :end', [':end' => $this->dateEnd])
                        ->orderBy('created_at', 'desc')
                        ->limit($this->limit, $this->offset)
                        ->get();
            
        $data = [];

        foreach ($results as $row) {
            $data[] = [
                'observable' => $row->observable,
                'created_at' => $row->created_at,
                'results' => json_decode($row->results, true)
            ];
        }

        return $data;
    }
}