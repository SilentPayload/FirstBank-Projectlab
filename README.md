# Banking SOC Incident Response Training Lab

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ⚠  SYNTHETIC TRAINING DATA ONLY  ⚠                      ║
║                                                                              ║
║  All IP addresses, account numbers, transaction records, hostnames,          ║
║  vulnerability findings, and log entries in this repository are ENTIRELY     ║
║  FABRICATED.  No real bank customers, employees, transactions, or live       ║
║  systems are represented.                                                    ║
║                                                                              ║
║  Authorised use: defensive cybersecurity education only, within the scope    ║
║  of the course for which this material was distributed.                      ║
║                                                                              ║
║  Do NOT use this material to simulate attacks against real systems.          ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## Scenario

**"Online Banking System Compromise" - FirstBank Nigeria (simulated)**

On 2026-02-20, FirstBank Nigeria's overnight fraud-detection system flagged
a cluster of large unauthorised wire transfers.  Students investigate how an
attacker exploited a SQL injection vulnerability in the customer login form,
performed lateral movement to the transaction server via a hijacked service
account, and executed a bulk-transfer script during a ~2-hour overnight window.

## Repository Structure

```
banking-soc-project/
├── docker-compose.yml          # Splunk + log-generator orchestration
├── .env.example                # Copy to .env; set STUDENT_SEED + SPLUNK_PASSWORD
├── data-generator/
│   ├── generate_logs.py        # Seeded synthetic log generator
│   └── Dockerfile
├── splunk/
│   └── banking_soc/            # Splunk app (inputs.conf, props.conf)
└── student/
    ├── README.md               # ← Student start here
    ├── analysis.py             # Skeleton for students to complete
    └── requirements.txt
```

## Quick Start (Students)

See **`student/README.md`** for full instructions.

```bash
cp .env.example .env          # set STUDENT_SEED and SPLUNK_PASSWORD
docker compose up --build     # generates logs + starts Splunk
# Open http://localhost:8000 after ~90 s
```

## Data Sources

| File | Description |
|------|-------------|
| `web_access.log` | Apache Combined Log - includes SQLi attack |
| `transaction.log` | Core banking transactions - includes fraudulent transfers |
| `windows_auth.log` | Windows Security Events - lateral movement + script exec |
| `nessus_scan.csv` | Static Nessus export - 10 hosts, one with SQLi-relevant CVE |

Each student's dataset is unique (seeded).  The entry-point host in
`nessus_scan.csv`, the attacker IP in `web_access.log`, and the confirmed-
compromise host flagged by `analysis.py` all refer to the same host - this
chain holds for every seed.

## Technology Stack

- **Splunk Enterprise 9.3.2** (free licence, ≤500 MB/day) - log analysis
- **Python 3.10+** - student analysis script
- **Docker Compose** - reproducible per-student environment

## Licence

This material is provided for authorised educational use only.  All synthetic
data is generated at runtime and is not stored in the repository.
