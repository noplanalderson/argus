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

        $history = DB::from('tb_analysis_history', 'a')->select([
                'a.history_id_uuid', 'b.ip_id_uuid', 'b.ip_address', 'a.overall_score', 'a.decision', 'a.created_at'
            ])->join('tb_ip_address AS b', 'a.ip_id_uuid = b.ip_id_uuid')
            ->where('ip_address', '=', $this->ip)
            ->orderBy('a.created_at', 'desc')
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