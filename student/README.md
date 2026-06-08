# FirstBank Nigeria - SOC Incident Response Training

> **DISCLAIMER - SYNTHETIC DATA**
> Every IP address, account number, transaction amount, hostname, log entry,
> and vulnerability finding in this exercise is entirely fabricated for
> authorized cybersecurity training purposes only.  No real bank customers,
> employees, transactions, or systems are represented.  Use strictly within
> the scope of this course.

---

## Scenario Brief

**Date of incident:** 2026-02-20 (overnight into 2026-02-21)
**Organisation:** FirstBank Nigeria (simulated)
**Reported by:** Automated fraud-detection alert at ~01:15 WAT

### What Happened

FirstBank Nigeria's overnight fraud-detection system flagged a cluster of
unusually large wire transfers originating from several customer accounts
between approximately 23:00 and 01:00 WAT.  No customer action was recorded
in the standard mobile-app logs during this window.

Your SOC team has been tasked with determining:

1. **How did the attacker get in?**
2. **How did they move through the environment?**
3. **What was the full impact?**
4. **What must be done immediately?**

You have access to:

| Data source | Description |
|-------------|-------------|
| `logs/web_access.log` | Apache access log from the internet-banking web server |
| `logs/transaction.log` | Core banking transaction log |
| `logs/windows_auth.log` | Windows Security Event Log from internal servers |
| `logs/nessus_scan.csv` | Static Nessus vulnerability scan (pre-incident) |
| `logs/scenario_manifest.json` | Seed-specific scenario metadata |

---

## Getting Started

### Prerequisites

- Docker Desktop (≥ 4.x) with **at least 4 GB RAM** allocated to Docker
- Python 3.10+
- Git

### 1 - Clone and configure

```bash
git clone <repo-url>
cd banking-soc-project
cp .env.example .env
```

Edit `.env` and set **your assigned `STUDENT_SEED`** (provided by your
instructor) and choose a Splunk password:

```
STUDENT_SEED=<your seed here>
SPLUNK_PASSWORD=Training123!
```

### 2 - Generate logs and start Splunk

```bash
docker compose up --build
```

Docker will:
1. Build and run the log generator (creates `logs/` in a Docker volume).
2. Start Splunk Enterprise 9.3.2.
3. Auto-configure Splunk to index all three log files.

Splunk takes ~90 seconds to fully start.

### 3 - Log in to Splunk

Open your browser: **http://localhost:8000**
Username: `admin`
Password: whatever you set in `.env` (default: `Training123!`)

### 4 - Verify ingestion

In Splunk Search, run:

```spl
index=banking_soc | stats count by sourcetype
```

You should see three sourcetypes:
- `access_combined`
- `banking_transaction`
- `windows_auth_training`

If any are missing, wait 30 seconds and retry (the monitor poller runs every 15 s).

### 5 - Pulling updates

```bash
git pull
```

If the Python skeleton is updated mid-exercise, run the above to fetch it.
Your `.env` and any completed code are not tracked by git and will not be overwritten.

---

## Phases and Tasks

### Phase 1 - Splunk Investigation (40 points)

Work in the Splunk Search interface.  Save each SPL query and its results as
a screenshot for inclusion in your Phase 3 report.

#### Task 1.1 - Identify the SQL injection (10 pts)

Find the SQL injection attempt on the `/login` endpoint.

- What is the **attacker's source IP address**?
- What **User-Agent** string indicates automated attack tooling?
- What is the **exact timestamp** of the first successful login after brute-force?
- Which **request URI** contains a visible SQLi payload?

Hint:
```spl
index=banking_soc sourcetype=access_combined
| search uri="/login" OR useragent=*sqlmap*
| table _time, src_ip, method, status, uri, useragent
| sort _time
```

#### Task 1.2 - Trace lateral movement (10 pts)

After gaining initial access, the attacker hijacked a service account and
pivoted to the transaction processing server.

- Which **service account** was used?
- From which host did the lateral movement originate?
- To which host did the attacker pivot?
- Which **Windows EventCodes** mark this activity?  (Hint: 4648, 4624, 5140)

Hint:
```spl
index=banking_soc sourcetype=windows_auth_training
| where EventCode IN ("4624","4648","4672","5140")
| table _time, EventCode, AccountName, SourceIP, WorkstationName, TargetServerName
| sort _time
```

#### Task 1.3 - Find the transfer script execution (10 pts)

The attacker executed a Python script on the transaction server.

- What is the **full command line** of the script?
- What **EventCode** captures process creation on Windows?  (4688)
- What is the **name of the batch file** passed to the script?

Hint:
```spl
index=banking_soc sourcetype=windows_auth_training EventCode=4688
| table _time, AccountName, NewProcessName, CommandLine, HostName
| sort _time
```

#### Task 1.4 - Isolate the fraudulent transfer window (10 pts)

- List all **fraudulent transaction IDs** (`TxnID`).
- What are the **victim account numbers** (`FromAccount`)?
- What are the **receiving (attacker) account numbers** (`ToAccount`)?
- What is the **total NGN amount** transferred?
- When did the **first and last** fraudulent transfers occur?

Hint:
```spl
index=banking_soc sourcetype=banking_transaction
| where like(InitiatedBy,"svc_%")
| table _time, TxnID, FromAccount, ToAccount, Amount, InitiatedBy
| sort _time
```

#### Task 1.5 - Reconstruct the full attack timeline

Combine all sources into a single ordered timeline.  Export the results as CSV
(click **Export → CSV** in Splunk) and save as `splunk_export.csv` - you will
need it for Phase 2.

```spl
index=banking_soc
| eval event_label=case(
    sourcetype="access_combined" AND (like(useragent,"%sqlmap%") OR like(uri,"%27%")),
        "SQLi activity",
    sourcetype="windows_auth_training" AND EventCode="4648",
        "Svc account session created",
    sourcetype="windows_auth_training" AND EventCode="4624" AND LogonType="3",
        "Lateral movement (network logon)",
    sourcetype="windows_auth_training" AND EventCode="4688",
        "Process execution",
    sourcetype="banking_transaction" AND like(InitiatedBy,"svc_%"),
        "Fraudulent wire transfer",
    true(), null()
  )
| where isnotnull(event_label)
| table _time, sourcetype, event_label, AccountName, SourceIP, Amount, CommandLine
| sort _time
```

---

### Phase 2 - Python Analysis (40 points)

Complete the five function stubs in `student/analysis.py`.

```bash
cd student
python analysis.py \
  --nessus  ../logs/nessus_scan.csv \
  --splunk  splunk_export.csv \
  --report  incident_report.txt
```

The script will raise `NotImplementedError` for each unimplemented function.
Work through them in order (Tasks 1 → 5); each feeds the next.

#### Task 2.1 - `parse_nessus_csv()` (8 pts)

Open `nessus_scan.csv` with `csv.DictReader`.  For each row, construct a
`Vulnerability` object.  Cast the `"CVSS v2.0 Base Score"` column to `float`;
skip rows where this fails.

#### Task 2.2 - `parse_splunk_export()` (8 pts)

Open the `splunk_export.csv` you exported in Task 1.5.  Parse the `_time`
column into a `datetime` object (Splunk exports ISO-8601 with timezone).
Populate `SplunkEvent.fields` with all CSV columns.  Return events sorted by
timestamp ascending.

Common Splunk timestamp format: `%Y-%m-%dT%H:%M:%S.%f%z`
Fallback: `%Y-%m-%d %H:%M:%S`

#### Task 2.3 - `score_risk()` (8 pts)

Implement the weighted-CVSS formula documented in the function's docstring.
Your implementation must satisfy:

- Empty input → `0.0`
- Single CVSS 10.0 Critical → score > 73
- Three or more CVSS 10.0 Criticals → score = 100.0

#### Task 2.4 - `flag_confirmed_compromise()` (8 pts)

Find the intersection of Nessus host IPs and IPs seen in attack-relevant
Splunk events (`EventCode` in `{4624, 4648, 4672, 4688, 4689, 5140}`).

Check the `SourceIP` field and the raw event text for IP addresses.

#### Task 2.5 - `generate_report()` (8 pts)

Write a plain-text report to `output_path` containing the six required sections
(listed in the function's docstring).  The file should be human-readable and
suitable for inclusion as an appendix to your Phase 3 submission.

---

### Phase 3 - Written Report (20 points + 10 bonus)

Submit a **15–20 page report** (PDF, 12pt, 1-inch margins) covering:

| Section | Points |
|---------|--------|
| Executive Summary (non-technical; for C-suite) | 4 |
| Customer Impact (accounts affected, total NGN exposed) | 4 |
| Nigerian Regulatory Considerations | 6 |
| Technical Remediation Recommendations | 6 |

**Regulatory section must reference at least two of:**

- **CBN Risk-Based Cybersecurity Framework (2022)** - 2-hour incident
  notification window; root-cause analysis within 5 business days.
- **BOFIA 2020 s.62** - mandatory disclosure of material cybersecurity incidents
  to the CBN Governor.
- **Nigeria Data Protection Act (NDPA) 2023 s.40** - notify NDPC within
  72 hours of confirmed data breach; notify affected customers without
  undue delay.
- **PCI DSS v4.0** - if payment card data may be in scope.

**Bonus (10 pts):** Correctly identify all compromised customer accounts (+5)
and map at least three attack steps to MITRE ATT&CK Enterprise TTPs (+5).

---

## Resource Notes

- Splunk requires **≥ 4 GB RAM** allocated to Docker.  On lower-RAM machines,
  expect slower startup; the 90-second wait may extend to 3–4 minutes.
- Splunk indexes data on disk inside the Docker volume.  If you restart
  the container, previously indexed data is preserved.
- Each student's dataset is **unique**.  Do not share seeds or answers with
  classmates; the grader cross-checks your findings against your seed.

---

## Submitting

1. `incident_report.txt` - generated by `analysis.py`
2. `student/analysis.py` - your completed Python file
3. Splunk screenshots (one per Task 1.x)
4. Phase 3 PDF report

Bundle as `<StudentID>_soc_lab.zip` and submit via the course portal.
