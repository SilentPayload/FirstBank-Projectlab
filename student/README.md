# FirstBank Nigeria - SOC Incident Response Training

> **DISCLAIMER - SYNTHETIC DATA**
> Every IP address, account number, transaction amount, hostname, log entry,
> and vulnerability finding in this exercise is entirely fabricated for
> authorized cybersecurity training purposes only. No real bank customers,
> employees, transactions, or systems are represented. Use strictly within
> the scope of this course.

---

## Table of Contents

1. [Scenario Brief](#scenario-brief)
2. [What You Will Need](#what-you-will-need)
3. [Step 1 - Install Prerequisites](#step-1---install-prerequisites)
4. [Step 2 - Clone the Repository](#step-2---clone-the-repository)
5. [Step 3 - Configure Your Environment](#step-3---configure-your-environment)
6. [Step 4 - Start the Lab](#step-4---start-the-lab)
7. [Step 5 - Log In to Splunk](#step-5---log-in-to-splunk)
8. [Step 6 - Verify Log Ingestion](#step-6---verify-log-ingestion)
9. [Phase 1 - Splunk Investigation](#phase-1---splunk-investigation-40-points)
10. [Phase 2 - Python Analysis](#phase-2---python-analysis-40-points)
11. [Phase 3 - Written Report](#phase-3---written-report-20-points--10-bonus)
12. [Submitting Your Work](#submitting-your-work)
13. [Troubleshooting](#troubleshooting)

---

## Scenario Brief

**Date of incident:** 2026-02-20 (overnight into 2026-02-21)
**Organisation:** FirstBank Nigeria (simulated)
**Reported by:** Automated fraud-detection alert at approximately 01:15 WAT

### What Happened

FirstBank Nigeria's overnight fraud-detection system flagged a cluster of
unusually large wire transfers originating from several customer accounts
between approximately 23:00 and 01:00 WAT. No customer action was recorded
in the standard mobile-app logs during this window.

Your SOC team has been tasked with determining:

1. **How did the attacker get in?**
2. **How did they move through the environment?**
3. **What was the full impact?**
4. **What must be done immediately?**

### Data Sources Available to You

| File | What it contains |
|------|-----------------|
| `logs/web_access.log` | Apache access log from the internet-banking web server. Contains normal user traffic and the attacker's SQL injection attempts. |
| `logs/transaction.log` | Core banking transaction log. Contains legitimate transfers and the fraudulent overnight wire transfers. |
| `logs/windows_auth.log` | Windows Security Event Log from internal servers. Contains logon events, privilege assignments, lateral movement, and process execution. |
| `logs/nessus_scan.csv` | A Nessus vulnerability scan taken before the incident. Identifies which hosts had known vulnerabilities. |
| `logs/scenario_manifest.json` | Metadata about your specific scenario (attacker IP, server names, etc.). Read this if you get stuck. |

> **Important:** Your dataset is unique. Every student received a different seed
> number from their instructor, which means your attacker IP, server IPs, account
> numbers, and timestamps are different from your classmates. Do not share seeds
> or compare specific answers - you will be graded against your own dataset only.

---

## What You Will Need

Before you begin, make sure you have the following installed on your machine:

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| Docker Desktop | 4.x or newer | Runs Splunk and the log generator in containers |
| Python | 3.10 or newer | Runs your analysis script in Phase 2 |
| Git | Any recent version | Clones the repository |
| A web browser | Chrome, Firefox, Edge | Access the Splunk web interface |

**RAM requirement:** Docker needs at least **4 GB of RAM** allocated to it.
On machines with less than 8 GB total RAM, Splunk may be slow to start.

---

## Step 1 - Install Prerequisites

### Docker Desktop

1. Go to [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
2. Download the installer for your operating system (Windows, Mac, or Linux)
3. Run the installer and follow the on-screen steps
4. Once installed, open Docker Desktop and wait for it to say **"Engine running"** in the bottom left

**Set Docker RAM allocation (important):**
- Open Docker Desktop
- Click the gear icon (Settings) in the top right
- Go to **Resources**
- Set **Memory** to at least **4 GB**
- Click **Apply and restart**

### Python 3.10+

- **Windows:** Download from [https://www.python.org/downloads/](https://www.python.org/downloads/) - tick "Add Python to PATH" during install
- **Mac:** Run `brew install python3` or download from python.org
- **Linux:** Run `sudo apt install python3` or `sudo dnf install python3`

Verify it installed correctly:
```bash
python --version
# or on some systems:
python3 --version
```
You should see `Python 3.10.x` or higher.

### Git

- **Windows:** Download from [https://git-scm.com/download/win](https://git-scm.com/download/win)
- **Mac:** Run `xcode-select --install` in Terminal, or `brew install git`
- **Linux:** Run `sudo apt install git` or `sudo dnf install git`

Verify:
```bash
git --version
```

---

## Step 2 - Clone the Repository

Open a terminal (Command Prompt or PowerShell on Windows, Terminal on Mac/Linux) and run:

```bash
git clone https://github.com/SilentPayload/FirstBank-Projectlab.git
cd FirstBank-Projectlab
```

You should now be inside the project folder. Run `ls` (Mac/Linux) or `dir` (Windows) to confirm you can see files like `docker-compose.yml`, `.env.example`, and a `student/` folder.

---

## Step 3 - Configure Your Environment

The lab uses a `.env` file to store your personal settings. You need to create this file from the provided example.

**On Mac/Linux:**
```bash
cp .env.example .env
```

**On Windows (Command Prompt):**
```cmd
copy .env.example .env
```

Now open `.env` in any text editor (Notepad, VS Code, nano, etc.). It looks like this:

```
STUDENT_SEED=12345
SPLUNK_PASSWORD=Training123!
```

Make two changes:

1. Replace `12345` with **the seed number your instructor gave you**
2. You can keep `Training123!` as your Splunk password or choose your own
   (it must be at least 8 characters with uppercase, lowercase, a number, and a special character)

Save and close the file.

> **Never share your `.env` file.** It contains your unique seed and is not tracked by Git.

---

## Step 4 - Start the Lab

Make sure Docker Desktop is running (you should see the Docker whale icon in your taskbar/menu bar and it should say "Engine running").

Then run:

```bash
docker compose up --build
```

This command does two things in order:

1. **Builds and runs the log generator** - creates your unique synthetic log files based on your seed
2. **Starts Splunk Enterprise** - a real SIEM that indexes and searches your logs

You will see a lot of output scroll past. This is normal. Wait until you see something like:

```
splunk  | Waiting for Splunk to be ready...
splunk  | Splunk is ready!
```

**Splunk takes approximately 90 seconds to fully start.** On slower machines or machines with less RAM, it may take up to 3-4 minutes. Do not close the terminal - leave it running in the background.

> If Docker says something like "Cannot connect to the Docker daemon", Docker Desktop is not running. Open it and wait for the engine to start, then try again.

---

## Step 5 - Log In to Splunk

Once Splunk is ready, open your web browser and go to:

```
http://localhost:8000
```

You will see the Splunk login page.

- **Username:** `admin`
- **Password:** whatever you set as `SPLUNK_PASSWORD` in your `.env` file (default: `Training123!`)

After logging in, you will land on the Splunk home page. To run searches:

1. Click **Search and Reporting** in the left sidebar (or the Apps menu at the top)
2. You will see a large search bar at the top - this is where you type SPL queries
3. Make sure the **time range** (top right of the search bar) is set to **All time** for this exercise

---

## Step 6 - Verify Log Ingestion

Before starting the investigation, confirm that all three log sources are indexed. In the Splunk search bar, type:

```spl
index=banking_soc | stats count by sourcetype
```

Press Enter or click the green search button.

You should see a table with three rows:

| sourcetype | count |
|------------|-------|
| access_combined | (some number) |
| banking_transaction | (some number) |
| windows_auth_training | (some number) |

If any sourcetype is missing, wait 30 seconds and run the search again. Splunk's monitor runs every 15 seconds. If they are still missing after 2 minutes, see the [Troubleshooting](#troubleshooting) section at the bottom of this file.

---

## Phase 1 - Splunk Investigation (40 points)

In this phase you will use Splunk's Search Processing Language (SPL) to investigate the incident across all three log sources.

**For each task:**
- Run the query in Splunk
- Read through the results carefully
- Take a **screenshot** of the results (you will need it for your Phase 3 report)
- Note down your answers

To take a screenshot showing your query and results together, make sure the search bar is visible in the screenshot.

---

### Task 1.1 - Identify the SQL Injection (10 pts)

The attacker used an automated SQL injection tool to brute-force the login page and gain access to the banking portal.

**Find answers to:**
- What is the attacker's source IP address?
- What User-Agent string identifies the automated attack tool?
- What is the exact timestamp of the first successful login (HTTP 200) by the attacker after the brute-force?
- Which request URI contains a visible SQL injection payload?

Run this query to get started:

```spl
index=banking_soc sourcetype=access_combined
| search uri="/login" OR useragent=*sqlmap*
| table _time, src_ip, method, status, uri, useragent
| sort _time
```

**Reading the results:**
- The `src_ip` column is where requests came from
- The `status` column is the HTTP response code - `401` means failed login, `200` means success
- The `useragent` column identifies the software making the request
- The `uri` column shows the exact URL path requested - look for anything that contains `%27` (URL-encoded single quote), `OR`, `1=1`, or similar SQL syntax

---

### Task 1.2 - Trace the Lateral Movement (10 pts)

After gaining initial access to the web server, the attacker hijacked a service account and moved laterally to the transaction processing server.

**Find answers to:**
- Which service account did the attacker hijack? (format: `svc_something`)
- From which host did the lateral movement originate? (this is the web server IP)
- To which host did the attacker pivot? (this is the transaction server hostname)
- Which Windows Event IDs mark this activity?

Run this query:

```spl
index=banking_soc sourcetype=windows_auth_training
| where EventCode IN ("4624","4648","4672","5140")
| table _time, EventCode, AccountName, SourceIP, WorkstationName, TargetServerName
| sort _time
```

**Understanding the Event Codes:**

| EventCode | What it means |
|-----------|--------------|
| 4648 | A logon was attempted using explicit credentials - attacker used a service account to authenticate |
| 4624 | Successful logon - `LogonType=3` means a network logon (remote connection), which indicates lateral movement |
| 4672 | Special privileges assigned to a new logon - indicates the account has elevated rights |
| 5140 | A network share was accessed - attacker connecting to a shared folder on the target server |

Look for events where `AccountName` starts with `svc_` and where `SourceIP` matches the web server IP you found in Task 1.1.

---

### Task 1.3 - Find the Transfer Script Execution (10 pts)

Once on the transaction server, the attacker executed a Python script to automate the fraudulent wire transfers.

**Find answers to:**
- What is the full command line of the script that was executed?
- What is Event ID 4688 and what does it capture?
- What is the name of the batch file passed to the script?

Run this query:

```spl
index=banking_soc sourcetype=windows_auth_training EventCode=4688
| table _time, AccountName, NewProcessName, CommandLine, HostName
| sort _time
```

**What to look for:**
- `EventCode=4688` is a Windows process creation event - it is logged every time a new process starts
- `NewProcessName` shows the executable that was launched
- `CommandLine` shows the full command including arguments - you are looking for a line that mentions `bulk_transfer.py` and a `.csv` batch file
- `AccountName` should match the service account you identified in Task 1.2

---

### Task 1.4 - Isolate the Fraudulent Transfer Window (10 pts)

The attacker's script initiated a series of wire transfers from victim accounts to attacker-controlled accounts.

**Find answers to:**
- List all fraudulent transaction IDs (TxnID)
- What are the victim account numbers (FromAccount)?
- What are the attacker's receiving account numbers (ToAccount)?
- What is the total NGN amount transferred?
- When did the first and last fraudulent transfers occur?

Run this query:

```spl
index=banking_soc sourcetype=banking_transaction
| where like(InitiatedBy,"svc_%")
| table _time, TxnID, FromAccount, ToAccount, Amount, InitiatedBy
| sort _time
```

**Why this works:** Legitimate transactions are initiated by human users (e.g., `adaobi.okafor`). The fraudulent ones were initiated by the service account the attacker hijacked, so filtering for `InitiatedBy` values that start with `svc_` isolates the fraudulent transfers.

To calculate the total amount, add this line to the query:

```spl
index=banking_soc sourcetype=banking_transaction
| where like(InitiatedBy,"svc_%")
| stats sum(Amount) as TotalNGN count as TxnCount
```

---

### Task 1.5 - Reconstruct the Full Attack Timeline

Combine all three sources into a single chronological timeline of attack activity. This gives you the complete picture of the incident from first probe to last fraudulent transfer.

Run this query:

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

**Export the results as a CSV file - you need this for Phase 2:**

1. After the search completes, look for the **Export** button above the results table (it may be under a small arrow or "..." menu)
2. Click **Export** then select **CSV**
3. Save the file as `splunk_export.csv`
4. Move or copy this file into the `student/` folder (same folder as `analysis.py`)

---

## Phase 2 - Python Analysis (40 points)

In this phase you will complete five Python functions in `student/analysis.py`. The script takes your Nessus scan data and Splunk export and produces a structured incident report.

### Before You Start

Open `student/analysis.py` in your code editor and read through the file. You will see:
- Two data model classes at the top (`Vulnerability` and `SplunkEvent`) - read their docstrings
- Five functions with `TODO` comments and `raise NotImplementedError(...)` - these are yours to implement
- Helper functions at the bottom marked "do not modify" - you can use these
- A `main()` function at the bottom marked "do not modify" - this calls all your functions

Work through the tasks in order (Task 2.1 to 2.5) because each function's output is passed into the next.

### Running the Script

From inside the `student/` directory:

```bash
cd student
python analysis.py \
  --nessus  ../logs/nessus_scan.csv \
  --splunk  splunk_export.csv \
  --report  incident_report.txt
```

On Windows use `python` instead of `python3`. If you get a `python: command not found` error, try `python3`.

When a function is not yet implemented, you will see:
```
NotImplementedError: parse_nessus_csv - implement me!
```
This is expected. Implement the function, then run again. Once all five are done, the script will print a summary and write `incident_report.txt`.

---

### Task 2.1 - `parse_nessus_csv()` (8 pts)

**Goal:** Read `nessus_scan.csv` and return a list of `Vulnerability` objects.

**How to approach it:**

```python
import csv

def parse_nessus_csv(filepath: str) -> list[Vulnerability]:
    results = []
    with open(filepath, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                cvss = float(row["CVSS v2.0 Base Score"])
            except (ValueError, KeyError):
                print(f"Skipping row - bad CVSS: {row}", file=sys.stderr)
                continue
            vuln = Vulnerability(
                plugin_id = row["Plugin ID"],
                cve       = row["CVE"],
                cvss      = cvss,
                risk      = row["Risk"],
                host      = row["Host"],
                port      = row["Port"],
                name      = row["Name"],
                synopsis  = row["Synopsis"],
            )
            results.append(vuln)
    return results
```

`csv.DictReader` reads each row as a dictionary where the keys are the column headers. The `Vulnerability` class constructor is already defined at the top of the file - just pass in the right values from the row.

---

### Task 2.2 - `parse_splunk_export()` (8 pts)

**Goal:** Read `splunk_export.csv` and return a list of `SplunkEvent` objects sorted by timestamp.

**How to approach it:**

```python
def parse_splunk_export(filepath: str) -> list[SplunkEvent]:
    results = []
    with open(filepath, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Parse the timestamp
            ts_str = row.get("_time", "")
            try:
                ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f%z")
            except ValueError:
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue  # skip rows with unparseable timestamps

            event = SplunkEvent(
                timestamp  = ts,
                sourcetype = row.get("sourcetype", ""),
                host       = row.get("host", ""),
                raw        = row.get("_raw", ""),
                fields     = dict(row),  # store the entire row as fields
            )
            results.append(event)

    return sorted(results, key=lambda e: e.timestamp)
```

The `%z` in the format string handles timezone offsets like `+01:00`. `SplunkEvent.fields` should contain all columns from the CSV row - just pass `dict(row)` directly.

---

### Task 2.3 - `score_risk()` (8 pts)

**Goal:** Calculate a risk score between 0.0 and 100.0 for a single host based on its vulnerabilities.

Use the formula already documented in the function's docstring:

```python
def score_risk(host_vulns: list[Vulnerability]) -> float:
    if not host_vulns:
        return 0.0

    severity_weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}

    weighted_cvss  = sum(v.cvss * severity_weight.get(v.risk, 0) for v in host_vulns)
    total_weight   = sum(severity_weight.get(v.risk, 0) for v in host_vulns)

    if total_weight == 0:
        return 0.0

    base_score      = (weighted_cvss / total_weight / 10.0) * 70
    num_criticals   = sum(1 for v in host_vulns if v.risk == "Critical")
    critical_bonus  = min(30, num_criticals * 10)

    return round(min(100.0, base_score + critical_bonus), 1)
```

**Verify your implementation satisfies:**
- `score_risk([])` returns `0.0`
- A single CVSS 10.0 Critical returns a score greater than 90
- Three or more CVSS 10.0 Criticals returns `100.0`

---

### Task 2.4 - `flag_confirmed_compromise()` (8 pts)

**Goal:** Return a sorted list of host IPs that appear in BOTH the Nessus data AND the Splunk attack events. These are hosts confirmed to be part of the attack path.

**How to approach it:**

```python
def flag_confirmed_compromise(
    nessus_data: list[Vulnerability],
    splunk_events: list[SplunkEvent],
) -> list[str]:

    # All IPs known from the Nessus scan
    nessus_ips = {v.host for v in nessus_data}

    # Event codes that indicate attack activity on a host
    attack_codes = {"4624", "4648", "4672", "4688", "4689", "5140"}

    # IPs seen in attack-relevant Splunk events
    seen_in_attack = set()
    for ev in splunk_events:
        if ev.sourcetype != "windows_auth_training":
            continue
        if ev.get("EventCode") not in attack_codes:
            continue
        # SourceIP is the connecting host (the entry point IP appears here
        # during lateral movement events)
        src = ev.get("SourceIP", "")
        if src in nessus_ips:
            seen_in_attack.add(src)

    return sorted(seen_in_attack)
```

The entry-point web server IP will appear as `SourceIP` in the lateral movement event (EventCode 4624, LogonType 3) because the attacker connected *from* the web server *to* the transaction server. That SourceIP will also be in the Nessus data because it was scanned.

---

### Task 2.5 - `generate_report()` (8 pts)

**Goal:** Write a plain-text incident report to a file with exactly six sections.

The `findings` dictionary is already populated by `main()` and passed to your function. The keys are:

| Key | Type | Contains |
|-----|------|---------|
| `entry_point` | str | IP of the web server where SQLi occurred |
| `attacker_ip` | str | External IP of the attacker |
| `attack_timeline` | list of (str, str) tuples | (timestamp, event description) pairs |
| `compromised_accounts` | list of str | Victim bank account numbers |
| `host_scores` | dict of str to float | {host_ip: risk_score} for all scanned hosts |
| `confirmed_hosts` | list of str | IPs confirmed as part of the attack path |

Your report must contain these six section headings **exactly** (the auto-grader checks for them):

```
EXECUTIVE SUMMARY
ATTACK TIMELINE
AFFECTED HOSTS AND RISK SCORES
COMPROMISED ACCOUNTS
CONFIRMED COMPROMISE HOSTS
RECOMMENDATIONS
```

Example structure:

```python
def generate_report(findings: dict, output_path: str) -> None:
    lines = []
    lines.append("=" * 60)
    lines.append("FIRSTBANK NIGERIA - INCIDENT RESPONSE REPORT")
    lines.append("=" * 60)
    lines.append("")

    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(f"Attacker IP   : {findings['attacker_ip']}")
    lines.append(f"Entry Point   : {findings['entry_point']}")
    lines.append("")

    lines.append("ATTACK TIMELINE")
    lines.append("-" * 40)
    for ts, desc in findings["attack_timeline"]:
        lines.append(f"  {ts}  {desc}")
    lines.append("")

    lines.append("AFFECTED HOSTS AND RISK SCORES")
    lines.append("-" * 40)
    for host, score in sorted(findings["host_scores"].items(), key=lambda x: -x[1]):
        lines.append(f"  {host:<18}  score={score:.1f}")
    lines.append("")

    lines.append("COMPROMISED ACCOUNTS")
    lines.append("-" * 40)
    for acct in findings["compromised_accounts"]:
        lines.append(f"  {acct}")
    lines.append("")

    lines.append("CONFIRMED COMPROMISE HOSTS")
    lines.append("-" * 40)
    for host in findings["confirmed_hosts"]:
        lines.append(f"  {host}")
    lines.append("")

    lines.append("RECOMMENDATIONS")
    lines.append("-" * 40)
    lines.append("  1. Immediately disable the compromised service account.")
    lines.append("  2. Patch the SQL injection vulnerability on the web server.")
    lines.append("  3. Review all wire transfers initiated during the attack window.")
    lines.append("  4. Reset credentials for all affected accounts.")
    lines.append("  5. Deploy a Web Application Firewall (WAF).")
    lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
```

You can expand the content in each section - more detail is better for your Phase 3 submission.

---

## Phase 3 - Written Report (20 points + 10 bonus)

Submit a **15-20 page PDF report** (12pt font, 1-inch margins) addressed to a fictional C-suite audience at FirstBank Nigeria.

### Required Sections

| Section | Points | What to include |
|---------|--------|----------------|
| Executive Summary | 4 | Non-technical overview. What happened, when, and the business impact. Write as if the reader has no technical background. |
| Customer Impact | 4 | Which accounts were affected, total NGN value exposed, and what the consequences are for affected customers. |
| Nigerian Regulatory Considerations | 6 | Which regulations were triggered and what FirstBank must do to comply. See the regulatory references below. |
| Technical Remediation Recommendations | 6 | Specific, actionable steps to prevent a recurrence. Reference the vulnerabilities found in the Nessus scan. |

### Regulatory References (at least two required)

- **CBN Risk-Based Cybersecurity Framework (2022):** FirstBank must notify the CBN within 2 hours of detecting the incident. A root-cause analysis report is due within 5 business days.
- **BOFIA 2020 Section 62:** Material cybersecurity incidents must be disclosed to the CBN Governor.
- **Nigeria Data Protection Act (NDPA) 2023 Section 40:** The NDPC must be notified within 72 hours of confirming a data breach. Affected customers must also be notified without undue delay.
- **PCI DSS v4.0:** If any payment card data was in scope, additional reporting and remediation obligations apply.

### Bonus Points (10 pts)

- **+5 pts:** Correctly identify all compromised customer account numbers (cross-checked against your seed)
- **+5 pts:** Map at least three distinct attack steps to MITRE ATT&CK Enterprise TTPs with tactic, technique ID, and technique name

Example ATT&CK mappings to get you started:

| Attack Step | Tactic | Technique |
|-------------|--------|-----------|
| SQL injection on login form | Initial Access | T1190 - Exploit Public-Facing Application |
| Hijacking a service account | Privilege Escalation | T1078 - Valid Accounts |
| Moving from web server to transaction server | Lateral Movement | T1021 - Remote Services |
| Executing the transfer script | Execution | T1059 - Command and Scripting Interpreter |

---

## Submitting Your Work

Bundle the following four items into a single ZIP file named `<YourStudentID>_soc_lab.zip`:

| File | Where to find it |
|------|-----------------|
| `incident_report.txt` | Generated by `analysis.py` in the `student/` folder |
| `analysis.py` | Your completed version in the `student/` folder |
| Splunk screenshots | One screenshot per Task 1.1 through 1.5 (5 screenshots minimum) |
| Phase 3 PDF report | Your written report |

Submit the ZIP via the course portal.

---

## Troubleshooting

### "Cannot connect to the Docker daemon"

Docker Desktop is not running. Open it from your Applications or Start menu and wait until you see "Engine running" before trying again.

### Splunk never starts / stays on "Waiting..."

Check how much RAM Docker has. Open Docker Desktop, go to Settings → Resources → Memory, and make sure it is set to at least 4 GB.

### Logs are not showing up in Splunk

First check that the log generator ran successfully:

```bash
docker compose ps
```

The `log-generator` service should show `Exited (0)`. If it shows a non-zero exit code, check its output:

```bash
docker compose logs log-generator
```

A common cause is an incorrect `STUDENT_SEED` value in `.env` - make sure it is a plain integer with no spaces or quotes.

If the generator ran fine but logs are still missing from Splunk, restart everything:

```bash
docker compose down -v
docker compose up --build
```

The `-v` flag removes the Docker volume so logs are regenerated fresh.

### Only two sourcetypes appear in Splunk (one is missing)

Wait an additional 30-60 seconds and re-run the verification query. Splunk's file monitor polls every 15 seconds. If the sourcetype is still missing after 2 minutes, run:

```bash
docker compose logs splunk | grep -i "error\|warn\|monitor"
```

### "python: command not found"

Try `python3` instead of `python`. On Windows, make sure you ticked "Add Python to PATH" during installation. If not, reinstall Python and tick that box.

### `ModuleNotFoundError` when running `analysis.py`

The script uses only Python standard library modules (`csv`, `datetime`, `pathlib`, `argparse`, `json`). No `pip install` is needed. If you see this error, check that your Python version is 3.10 or higher:

```bash
python --version
```

### Splunk password forgotten

Stop the Splunk container and reset the password:

```bash
docker compose stop splunk
docker compose run --rm splunk entrypoint.sh splunk edit user admin -password NewPass123! -auth admin:OldPassword
docker compose start splunk
```

Or destroy and recreate the Splunk container (your log volume is separate and will be preserved):

```bash
docker compose rm -f splunk
docker compose up splunk -d
```

### Getting updates from your instructor mid-exercise

```bash
git pull
```

Your `.env` file and any code you have written will not be overwritten by a pull because they are not tracked by Git.
