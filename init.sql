USE app_db;
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
    overall_score FLOAT NOT NULL,
    decision JSON NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NULL,
    FOREIGN KEY (ip_id_uuid) REFERENCES tb_ip_address(ip_id_uuid)
);