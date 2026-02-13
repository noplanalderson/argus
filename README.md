# ARGUS v4.0.0

## Adaptive Reputation & Guarding Unified System

ARGUS is a research-grade Threat Intelligence Aggregation and Automated
IP Blocking System designed to integrate multiple Threat Intelligence
Platforms (TIP) and automate firewall enforcement.

It aggregates reputation data from heterogeneous intelligence sources,
computes a weighted threat score, and optionally performs automated
blocking actions on supported firewalls.

------------------------------------------------------------------------

# 1. Research Objectives

ARGUS is designed for:

-   Threat Intelligence correlation research
-   Automated SOC workflow experimentation
-   Reputation scoring model evaluation
-   Firewall automation studies
-   Threat feed normalization research

------------------------------------------------------------------------

# 2. Core Architecture

Observable (IP / Hash) ↓ Multi-Source Threat Intelligence Aggregation ↓
Weighted Scoring Engine ↓ Decision Engine ↓ Firewall Automation (Sangfor
/ Mikrotik) ↓ Logging & Reporting (PDF / Nextcloud)

------------------------------------------------------------------------

# 3. Threat Intelligence Sources

## IP Intelligence

-   VirusTotal
-   AbuseIPDB
-   CrowdSec
-   CriminalIP
-   ThreatBook
-   Internal Blocklist
-   OpenCTI (optional)

## Hash Intelligence

-   VirusTotal
-   Yaraify
-   Malware Bazaar
-   Malprobe
-   OpenCTI (optional)

------------------------------------------------------------------------

# 4. Scoring Engine Model

ARGUS uses a weighted scoring model.

## IP Weights

-   VirusTotal: 0.10
-   Blocklist: 0.30 (0.25 if OpenCTI enabled)
-   AbuseIPDB: 0.30
-   CrowdSec: 0.15
-   CriminalIP: 0.05
-   ThreatBook: 0.10
-   OpenCTI: 0.05 (optional)

## Hash Weights

-   VirusTotal: 0.35 (0.30 if OpenCTI enabled)
-   Yaraify: 0.15 (0.05 if OpenCTI enabled)
-   Malware Bazaar: 0.20 (0.15 if OpenCTI enabled)
-   Malprobe: 0.30 (0.25 if OpenCTI enabled)
-   OpenCTI: 0.25 (optional)

Weights dynamically adjust if OpenCTI is configured.

------------------------------------------------------------------------

# 5. API Endpoints

GET /home\
GET /check\
POST /analyze\
POST /action\
POST /blocklist\
POST /jobs\
GET /create24h-report

Authentication required via Bearer Token.

------------------------------------------------------------------------

# 6. Environment Configuration

## Root .env

MYSQL_ROOT_PASSWORD= MYSQL_DATABASE= MYSQL_USER= MYSQL_PASSWORD=

## ./argus/.env

DB_HOST=mariadb DB_USER= DB_PASS= DB_NAME=

API_AUTH_TOKEN=

FW_TYPE=SANGFOR or MIKROTIK FW_HOST= FW_AUTH= FW_USER= FW_PASS= FW_PORT=

OPENCTI_URL= OPENCTI_API_KEY=

VT_API_KEY= CROWDSEC_API_KEY= ABUSECH_API_KEY= MALPROBE_API_KEY=
ABUSEIP_API_KEY= CRIMINALIP_API_KEY= THREATBOOK_API_KEY=

ARGUS_CONCURRENCY=7 FORCE_REANALYZE=90

NEXTCLOUD_BASE= NEXTCLOUD_DAV= NEXTCLOUD_DIR= NEXTCLOUD_USER=
NEXTCLOUD_PWD=

OPENAI_KEY= OPENAI_ORG= OPENAI_PROJ=

------------------------------------------------------------------------

# 7. Docker Deployment

Development:

make dev-build\
make dev-up\
make dev-logs\
make dev-shell

Production:

make prod-build\
make prod-up\
make prod-logs

Utilities:

make composer-install\
make composer-update\
make db-backup\
make monitor\
make clean

------------------------------------------------------------------------

# 8. Logging

Threat Analysis Log: logs/argus_tip.log

Blocklist Execution Log: /var/log/ip-blocklist.log

------------------------------------------------------------------------

# 9. 24-Hour PDF Report

The system can generate a 24-hour blocklist report including:

-   Threat distribution
-   Top attacking ASNs
-   Risk scoring distribution
-   Permanent vs Temporary block analysis

------------------------------------------------------------------------

# 10. Security Considerations

-   All endpoints require Bearer token authentication
-   API keys must be stored securely
-   Firewall credentials must not be exposed
-   Rate limiting recommended in production
-   TLS termination required in public deployment

------------------------------------------------------------------------

# 11. Research Extensions

Possible future research directions:

-   Machine Learning based scoring
-   Behavioral anomaly scoring
-   Adaptive weight tuning
-   Threat actor clustering
-   Graph-based intelligence correlation

------------------------------------------------------------------------

Author: Muhammad Ridwan Na'im Version: 4.0.0
