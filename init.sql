USE app_db;

CREATE TABLE IF NOT EXISTS `tb_jobs` (
  `job_id` varchar(36) NOT NULL,
  `observable` text NOT NULL,
  `results` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`job_id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci ROW_FORMAT=DYNAMIC;

CREATE TABLE IF NOT EXISTS tb_ip_address (
  `ip_id_uuid` varchar(36) NOT NULL,
  `ip_address` char(128) NOT NULL,
  `isp` char(255) DEFAULT NULL,
  `classification` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`classification`)),
  `location` char(128) DEFAULT NULL,
  `country_code` char(3) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`ip_id_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS tb_analysis_history (
  `history_id_uuid` varchar(36) NOT NULL,
  `ip_id_uuid` varchar(36) NOT NULL,
  `crowdsec_score` float NOT NULL,
  `vt_score` float NOT NULL,
  `abuseip_score` float NOT NULL,
  `criminalip_score` float DEFAULT NULL,
  `blocklist_score` float DEFAULT NULL,
  `opencti_score` float DEFAULT NULL,
  `threatbook_score` float DEFAULT NULL,
  `wazuh_score` float DEFAULT NULL,
  `tip_score` float DEFAULT NULL,
  `overall_score` float NOT NULL,
  `decision` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`decision`)),
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`history_id_uuid`),
  KEY `tb_analysis_history_ibfk_1` (`ip_id_uuid`),
  CONSTRAINT `tb_analysis_history_ibfk_1` FOREIGN KEY (`ip_id_uuid`) REFERENCES `tb_ip_address` (`ip_id_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS tb_file_hash (
  `hash_id` varchar(255) NOT NULL,
  `file_hash` varchar(255) NOT NULL,
  `observable_name` varchar(255) DEFAULT NULL,
  `classification` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`classification`)),
  `vt_score` float DEFAULT NULL,
  `mb_score` float DEFAULT NULL,
  `yara_score` float DEFAULT NULL,
  `malprobe_score` float DEFAULT NULL,
  `opencti_score` float DEFAULT NULL,
  `overall_score` float NOT NULL,
  `decision` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`decision`)),
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`hash_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;