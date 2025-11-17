USE app_db;

CREATE TABLE IF NOT EXISTS tb_jobs (
    job_id VARCHAR(36) NOT NULL PRIMARY KEY,
    observable TEXT NOT NULL,
    results JSON NOT NULL,
    created_at DATETIME NULL
);

CREATE TABLE IF NOT EXISTS tb_ip_address (
    ip_id_uuid VARCHAR(36) NOT NULL PRIMARY KEY,
    ip_address CHAR(128) NOT NULL,
    isp CHAR(255) NULL,
    classification JSON NULL,
    location CHAR(128) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NULL
);

CREATE TABLE IF NOT EXISTS tb_analysis_history (
    history_id_uuid VARCHAR(36) NOT NULL PRIMARY KEY,
    ip_id_uuid VARCHAR(36) NOT NULL,
    crowdsec_score FLOAT NOT NULL,
    vt_score FLOAT NOT NULL,
    abuseip_score FLOAT NOT NULL,
    criminalip_score FLOAT NOT NULL,
    blocklist_score FLOAT NOT NULL,
    opencti_score FLOAT NULL,
    tip_score FLOAT NULL,
    wazuh_score FLOAT NULL,
    overall_score FLOAT NOT NULL,
    decision JSON NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NULL,
    FOREIGN KEY (ip_id_uuid) REFERENCES tb_ip_address(ip_id_uuid)
);

CREATE TABLE IF NOT EXISTS tb_file_hash (
    hash_id VARCHAR(255) NOT NULL PRIMARY KEY,
    file_hash VARCHAR(255) NOT NULL,
    observable_name VARCHAR(255) NULL,
    classification JSON NULL,
    vt_score FLOAT NULL,
    mb_score FLOAT NULL,
    yara_score FLOAT NULL,
    malprobe_score FLOAT NULL,
    opencti_score FLOAT NULL,
    overall_score FLOAT NOT NULL,
    decision JSON NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);