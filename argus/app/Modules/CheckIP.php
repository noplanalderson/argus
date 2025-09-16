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

        $history = DB::from('tb_analysis_history')
                        ->select(
                            'history_id_uuid, tb_analysis_history.ip_id_uuid, 
                            tb_ip_address.ip_address, tb_analysis_history.overall_score, tb_analysis_history.decision, 
                            tb_analysis_history.created_at')
                        ->join('tb_ip_address', 'tb_analysis_history.ip_id_uuid = tb_ip_address.ip_id_uuid')
                        ->where('ip_address', '=', $this->ip)
                        ->orderBy('tb_analysis_history.created_at', 'desc')
                        ->limit(1)->get();
            
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