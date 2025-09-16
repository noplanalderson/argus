<?php
namespace App\Modules;
use App\Cores\DB;
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

        $history = DB::table('tb_analysis_history')->select('tb_analysis_history.*, ip_address')
                            ->join('tb_ip_address', 'tb_ip_address.ip_id_uuid = tb_analysis_history.ip_id_uuid', 'inner')
                            ->where('ip_address', '=', $this->ip)->orderBy('created_at', 'desc')->first();
            
        if(!empty($history['history_id_uuid']))
        {
            $lastAnalysis = strtotime($history['created_at']);
            $lastAnalysis = (time() - $lastAnalysis) < (3 * 86400);
    
            if ($lastAnalysis && isset($history['decision'])) {
                $history['decision'] = json_decode($history['decision'], true);
    
                if($history['decision']['blockmode'] !== false) {
                    $result = [
                        'last_analyze' => $history['created_at'],
                        'already_analyzed' => $lastAnalysis,
                        'blockmode' => $history['decision']['blockmode']
                    ];
                }
            }
        }

        return $result;
    }
}