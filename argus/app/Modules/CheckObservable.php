<?php
namespace App\Modules;
use App\Cores\DB;
class CheckObservable
{
    protected $observable;

    protected $type;

    public function __construct($observable, $type)
    {
        $this->observable = $observable;
        $this->type = $type;
    }

    public function check()
    {
        $result = [
            'already_analyzed' => false,
            'blockmode' => false 
        ];

        if($this->type == 'ip')
        {
            $history = DB::table('tb_analysis_history')->select('tb_analysis_history.*, ip_address')
                                ->join('tb_ip_address', 'tb_ip_address.ip_id_uuid = tb_analysis_history.ip_id_uuid', 'inner')
                                ->where('ip_address', '=', $this->observable)->orderBy('tb_analysis_history.created_at', 'desc')->first();
                                
            if(!empty($history['history_id_uuid']))
            {
                $decision = json_decode($history['decision'], true);
                $blocked        = (int)$decision['blockmode'];
                $lastAnalysis   = strtotime($history['created_at']);
                $unblock        = $lastAnalysis + ($blocked * 86400);

                if (strtotime("now") < $unblock) {
        
                    if($decision['blockmode'] !== false) {
                        $result = [
                            'last_analyze' => $history['created_at'],
                            'already_analyzed' => true,
                            'blockmode' => $decision['blockmode']
                        ];
                    }
                }
            }
        }
        else 
        {
            
            $history = DB::table('tb_file_hash')->select('*')
                                ->where('observable_name', '=', $this->observable)->orderBy('tb_file_hash.created_at', 'desc')->first();
                
            if(!empty($history['hash_id']))
            {
                $lastAnalysis   = strtotime($history['created_at']);
                $reanalyzeTime  = $_ENV['FORCE_REANALYZE'] * 24 * 60 * 60;
                $unblock        = $lastAnalysis + $reanalyzeTime;

                if (strtotime("now") < $unblock) {
                    $result = [
                        'last_analyze' => $history['created_at'],
                        'already_analyzed' => true
                    ];
                }
            }
        }

        return $result;
    }
}