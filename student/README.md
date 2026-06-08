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

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| Docker Engine | 24.x or newer | Runs Splunk and the log generator in containers |
| Docker Compose | 2.x or newer | Orchestrates the containers |
| Python | 3.10 or newer | Runs your analysis script in Phase 2 |
| Git | Any recent version | Clones the repository |
| A web browser | Firefox or Chromium | Access the Splunk web interface |

**RAM requirement:** Docker needs at least **4 GB of RAM** available.
On machines with less than 8 GB total RAM, Splunk may be slow to start.

---

## Step 1 - Install Prerequisites

Open a terminal. All commands below are run as your regular user unless `sudo` is shown.

### Docker Engine and Docker Compose

**Debian / Ubuntu / Kali:**

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

> If you are on **Ubuntu** replace `debian` with `ubuntu` in the URL above.
> If you are on **Kali**, the Debian instructions above work as-is.

**Fedora / RHEL / Rocky:**

```bash
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

**Add your user to the docker group** (so you can run docker without sudo):

```bash
sudo usermod -aG docker $USER
newgrp docker
```

Verify Docker is working:

```bash
docker --version
docker compose version
```

You should see version numbers for both. If `docker compose version` fails, your system may have the older standalone `docker-compose` binary - in that case replace `docker compose` with `docker-compose` everywhere in this guide.

### Python 3.10+

**Debian / Ubuntu / Kali:**

```bash
sudo apt install -y python3 python3-pip
```

**Fedora / RHEL:**

```bash
sudo dnf install -y python3
```

Verify:

```bash
python3 --version
```

You should see `Python 3.10.x` or higher.

### Git

**Debian / Ubuntu / Kali:**

```bash
sudo apt install -y git
```

**Fedora / RHEL:**

```bash
sudo dnf install -y git
```

Verify:

```bash
git --version
```

---

## Step 2 - Clone the Repository

In your terminal, navigate to wherever you keep your coursework, then clone:

```bash
git clone https://github.com/SilentPayload/FirstBank-Projectlab.git
cd FirstBank-Projectlab
```

Confirm the files are there:

```bash
ls
```

You should see `docker-compose.yml`, `.env.example`, `student/`, `data-generator/`, and `splunk/`.

---

## Step 3 - Configure Your Environment

The lab uses a `.env` file to hold your personal settings. Create it from the example:

```bash
cp .env.example .env
```

Open `.env` in a text editor:

```bash
nano .env
```

It looks like this:

```
STUDENT_SEED=12345
SPLUNK_PASSWORD=Training123!
```

Make two changes:

1. Replace `12345` with **the seed number your instructor gave you**
2. You can keep `Training123!` as your Splunk password or choose your own.
   It must be at least 8 characters and contain uppercase, lowercase, a digit, and a special character.

Save and exit (`Ctrl+O` then `Enter` then `Ctrl+X` in nano).

> **Never share your `.env` file.** It contains your unique seed and is not tracked by Git.

---

## Step 4 - Start the Lab

Make sure the Docker service is running:

```bash
sudo systemctl status docker
```

If it says `inactive`, start it:

```bash
sudo systemctl start docker
```

Then launch the lab from the project root:

```bash
docker compose up --build
```

This does two things in order:

1. **Builds and runs the log generator** - creates your unique synthetic log files based on your seed
2. **Starts Splunk Enterprise** - a full SIEM that indexes and searches your logs

You will see a lot of output scroll past. This is normal. Wait until you see:

```
splunk  | Waiting for Splunk to be ready...
splunk  | Splunk is ready!
```

**Splunk takes approximately 90 seconds to fully start.** On slower machines or machines with less than 8 GB RAM, it may take up to 3-4 minutes. Leave the terminal running - do not close it.

To run subsequent commands while the lab is running, open a second terminal tab (`Ctrl+Shift+T` in most Linux terminals).

---

## Step 5 - Log In to Splunk

Once Splunk is ready, open your browser and go to:

```
http://localhost:8000
```

You will see the Splunk login page.

- **Username:** `admin`
- **Password:** whatever you set as `SPLUNK_PASSWORD` in your `.env` file (default: `Training123!`)

After logging in, you land on the Splunk home page. To run searches:

1. Click **Search and Reporting** in the left sidebar (or from the Apps menu at the top)
2. You will see a large search bar at the top - this is where you type SPL queries
3. Set the **time range picker** (top right of the search bar) to **All time** for this exercise

---

## Step 6 - Verify Log Ingestion

Before starting the investigation, confirm that all three log sources are indexed. In the Splunk search bar type:

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

If any sourcetype is missing, wait 30 seconds and run the search again. Splunk's file monitor polls every 15 seconds. If they are still missing after 2 minutes, see the [Troubleshooting](#troubleshooting) section.

---

## Phase 1 - Splunk Investigation (40 points)

In this phase you use Splunk's Search Processing Language (SPL) to investigate the incident across all three log sources.

**For each task:**
- Paste the query into the Splunk search bar and run it
- Read through the results carefully
- Take a **screenshot** showing both the query and the results table (you will submit these)
- Write down your answers

---

### Task 1.1 - Identify the SQL Injection (10 pts)

The attacker used an automated SQL injection tool to brute-force the login page and gain access to the banking portal.

**Find answers to:**
- What is the attacker's source IP address?
- What User-Agent string identifies the automated attack tool?
- What is the exact timestamp of the first successful login (HTTP 200) by the attacker?
- Which request URI contains a visible SQL injection payload?

```spl
index=banking_soc sourcetype=access_combined
| search uri="/login" OR useragent=*sqlmap*
| table _time, src_ip, method, status, uri, useragent
| sort _time
```

**Reading the results:**

| Column | What it means |
|--------|--------------|
| `src_ip` | IP address the request came from |
| `status` | HTTP response code - `401` is a failed login, `200` is success |
| `useragent` | The software that made the request - automated tools have distinctive strings |
| `uri` | The exact URL path - look for `%27` (URL-encoded single quote `'`), `OR`, `1=1`, or `--` which are SQL injection markers |

---

### Task 1.2 - Trace the Lateral Movement (10 pts)

After gaining access to the web server, the attacker hijacked a service account and moved laterally to the transaction processing server.

**Find answers to:**
- Which service account did the attacker hijack? (format: `svc_something`)
- From which host did the lateral movement originate?
- To which host did the attacker pivot?
- Which Windows Event IDs mark this activity?

```spl
index=banking_soc sourcetype=windows_auth_training
| where EventCode IN ("4624","4648","4672","5140")
| table _time, EventCode, AccountName, SourceIP, WorkstationName, TargetServerName
| sort _time
```

**Understanding the Event Codes:**

| EventCode | What it means |
|-----------|--------------|
| 4648 | Logon attempted using explicit credentials - attacker authenticated using the hijacked service account |
| 4624 | Successful logon - when `LogonType=3` this is a network logon, meaning a remote connection (lateral movement) |
| 4672 | Special privileges assigned to a new logon - the account has elevated rights |
| 5140 | Network share accessed - attacker accessing a shared folder on the target server |

Look for events where `AccountName` starts with `svc_` and where `SourceIP` matches the web server IP you found in Task 1.1.

---

### Task 1.3 - Find the Transfer Script Execution (10 pts)

Once on the transaction server, the attacker executed a Python script to automate the fraudulent transfers.

**Find answers to:**
- What is the full command line of the executed script?
- What does EventCode 4688 capture?
- What is the name of the batch file passed to the script?

```spl
index=banking_soc sourcetype=windows_auth_training EventCode=4688
| table _time, AccountName, NewProcessName, CommandLine, HostName
| sort _time
```

**What to look for:**

| Column | What it means |
|--------|--------------|
| `EventCode=4688` | Windows process creation event - logged every time a new process starts |
| `NewProcessName` | The executable that was launched |
| `CommandLine` | Full command including all arguments - look for `bulk_transfer.py` and a `.csv` filename |
| `AccountName` | Should match the service account from Task 1.2 |

---

### Task 1.4 - Isolate the Fraudulent Transfer Window (10 pts)

The attacker's script initiated a series of wire transfers from victim accounts to attacker-controlled accounts.

**Find answers to:**
- All fraudulent transaction IDs (TxnID)
- Victim account numbers (FromAccount)
- Attacker receiving account numbers (ToAccount)
- Total NGN amount transferred
- Timestamps of the first and last fraudulent transfer

```spl
index=banking_soc sourcetype=banking_transaction
| where like(InitiatedBy,"svc_%")
| table _time, TxnID, FromAccount, ToAccount, Amount, InitiatedBy
| sort _time
```

**Why this works:** Legitimate transactions are initiated by named human users (e.g. `adaobi.okafor`). The fraudulent ones were initiated by the hijacked service account, so filtering for `InitiatedBy` values starting with `svc_` isolates only the attacker's transactions.

To calculate the total amount transferred:

```spl
index=banking_soc sourcetype=banking_transaction
| where like(InitiatedBy,"svc_%")
| stats sum(Amount) as TotalNGN count as TxnCount
```

---

### Task 1.5 - Reconstruct the Full Attack Timeline

Combine all three log sources into a single chronological timeline. This gives you the complete picture from the first probe to the last fraudulent transfer.

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

**Export as CSV - you need this for Phase 2:**

1. After the search completes, click the **Export** button above the results table
2. Select **CSV**
3. Save the file as `splunk_export.csv`
4. Copy it into the `student/` folder (same folder as `analysis.py`):

```bash
cp ~/Downloads/splunk_export.csv student/splunk_export.csv
```

---

## Phase 2 - Python Analysis (40 points)

In this phase you complete five Python functions in `student/analysis.py`. The script reads your Nessus data and Splunk export and writes a structured incident report.

### Before You Start

Open `student/analysis.py` in your editor and read through the whole file first. You will find:

- Two data model classes (`Vulnerability` and `SplunkEvent`) at the top - read their docstrings to understand their fields
- Five functions with `# TODO` and `raise NotImplementedError(...)` - these are yours to implement
- Helper functions near the bottom marked "do not modify" - you can call these
- A `main()` block at the bottom marked "do not modify" - this wires everything together

Work through the tasks in order (2.1 through 2.5) because each function's output feeds into the next.

### Running the Script

From the project root:

```bash
cd student
python3 analysis.py \
  --nessus  ../logs/nessus_scan.csv \
  --splunk  splunk_export.csv \
  --report  incident_report.txt
```

When a function is not yet implemented you will see:

```
NotImplementedError: parse_nessus_csv - implement me!
```

This is expected. Implement the function, save the file, and run again. Once all five functions are done the script prints a summary and writes `incident_report.txt`.

---

### Task 2.1 - `parse_nessus_csv()` (8 pts)

**Goal:** Read `nessus_scan.csv` and return a list of `Vulnerability` objects.

```python
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

`csv.DictReader` reads each row as a dictionary where keys are the column headers. The `Vulnerability` class is already defined at the top of the file - just pass in the values from each row.

---

### Task 2.2 - `parse_splunk_export()` (8 pts)

**Goal:** Read `splunk_export.csv` and return a list of `SplunkEvent` objects sorted by timestamp.

```python
def parse_splunk_export(filepath: str) -> list[SplunkEvent]:
    results = []
    with open(filepath, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts_str = row.get("_time", "")
            try:
                ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f%z")
            except ValueError:
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
            event = SplunkEvent(
                timestamp  = ts,
                sourcetype = row.get("sourcetype", ""),
                host       = row.get("host", ""),
                raw        = row.get("_raw", ""),
                fields     = dict(row),
            )
            results.append(event)
    return sorted(results, key=lambda e: e.timestamp)
```

The `%z` in the format string handles timezone offsets like `+01:00`. Pass `dict(row)` directly to `fields` to store all CSV columns.

---

### Task 2.3 - `score_risk()` (8 pts)

**Goal:** Calculate a risk score between 0.0 and 100.0 for a single host based on its vulnerabilities.

```python
def score_risk(host_vulns: list[Vulnerability]) -> float:
    if not host_vulns:
        return 0.0

    severity_weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}

    weighted_cvss = sum(v.cvss * severity_weight.get(v.risk, 0) for v in host_vulns)
    total_weight  = sum(severity_weight.get(v.risk, 0) for v in host_vulns)

    if total_weight == 0:
        return 0.0

    base_score     = (weighted_cvss / total_weight / 10.0) * 70
    num_criticals  = sum(1 for v in host_vulns if v.risk == "Critical")
    critical_bonus = min(30, num_criticals * 10)

    return round(min(100.0, base_score + critical_bonus), 1)
```

**Verify your implementation satisfies:**
- `score_risk([])` returns `0.0`
- A single CVSS 10.0 Critical returns a score greater than 90
- Three or more CVSS 10.0 Criticals returns `100.0`

---

### Task 2.4 - `flag_confirmed_compromise()` (8 pts)

**Goal:** Return a sorted list of host IPs that appear in BOTH the Nessus data AND the Splunk attack events.

```python
def flag_confirmed_compromise(
    nessus_data: list[Vulnerability],
    splunk_events: list[SplunkEvent],
) -> list[str]:

    nessus_ips   = {v.host for v in nessus_data}
    attack_codes = {"4624", "4648", "4672", "4688", "4689", "5140"}

    seen_in_attack = set()
    for ev in splunk_events:
        if ev.sourcetype != "windows_auth_training":
            continue
        if ev.get("EventCode") not in attack_codes:
            continue
        src = ev.get("SourceIP", "")
        if src in nessus_ips:
            seen_in_attack.add(src)

    return sorted(seen_in_attack)
```

The entry-point web server IP appears as `SourceIP` in the lateral movement event (EventCode 4624, LogonType 3) because the attacker connected *from* the web server *to* the transaction server. That same IP is in the Nessus data because it was scanned before the incident.

---

### Task 2.5 - `generate_report()` (8 pts)

**Goal:** Write a plain-text incident report with exactly six sections.

The `findings` dictionary passed to your function contains:

| Key | Type | Contents |
|-----|------|---------|
| `entry_point` | str | IP of the web server where SQLi occurred |
| `attacker_ip` | str | External IP of the attacker |
| `attack_timeline` | list of (str, str) | (timestamp, event description) pairs |
| `compromised_accounts` | list of str | Victim bank account numbers |
| `host_scores` | dict str to float | {host_ip: risk_score} for all scanned hosts |
| `confirmed_hosts` | list of str | IPs confirmed as part of the attack path |

Your report must contain these six headings **exactly** (the auto-grader checks for them):

```
EXECUTIVE SUMMARY
ATTACK TIMELINE
AFFECTED HOSTS AND RISK SCORES
COMPROMISED ACCOUNTS
CONFIRMED COMPROMISE HOSTS
RECOMMENDATIONS
```

Example implementation:

```python
def generate_report(findings: dict, output_path: str) -> None:
    lines = []
    lines.append("=" * 60)
    lines.append("FIRSTBANK NIGERIA - INCIDENT RESPONSE REPORT")
    lines.append("=" * 60)
    lines.append("")

    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(f"Attacker IP  : {findings['attacker_ip']}")
    lines.append(f"Entry Point  : {findings['entry_point']}")
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
    lines.append("  3. Review all wire transfers during the attack window.")
    lines.append("  4. Reset credentials for all affected accounts.")
    lines.append("  5. Deploy a Web Application Firewall (WAF).")
    lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
```

You can expand every section with more detail - more depth is better for your Phase 3 submission.

---

## Phase 3 - Written Report (20 points + 10 bonus)

Submit a **15-20 page PDF report** (12pt font, 1-inch margins) addressed to a fictional C-suite audience at FirstBank Nigeria.

### Required Sections

| Section | Points | What to include |
|---------|--------|----------------|
| Executive Summary | 4 | Non-technical overview of what happened, when, and the business impact. Write as if the reader has no technical background. |
| Customer Impact | 4 | Which accounts were affected, total NGN value exposed, and consequences for customers. |
| Nigerian Regulatory Considerations | 6 | Which regulations apply and what FirstBank must do to comply. At least two references required (see below). |
| Technical Remediation Recommendations | 6 | Specific, actionable steps to prevent a recurrence. Reference the vulnerabilities from the Nessus scan. |

### Regulatory References (at least two required)

- **CBN Risk-Based Cybersecurity Framework (2022):** Notify the CBN within 2 hours of detecting the incident. Root-cause analysis report due within 5 business days.
- **BOFIA 2020 Section 62:** Material cybersecurity incidents must be disclosed to the CBN Governor.
- **Nigeria Data Protection Act (NDPA) 2023 Section 40:** Notify the NDPC within 72 hours of confirming a data breach. Notify affected customers without undue delay.
- **PCI DSS v4.0:** If payment card data was in scope, additional reporting and remediation obligations apply.

### Bonus Points (10 pts)

- **+5 pts:** Correctly identify all compromised customer account numbers
- **+5 pts:** Map at least three attack steps to MITRE ATT&CK Enterprise TTPs with tactic, technique ID, and technique name

Example ATT&CK mappings:

| Attack Step | Tactic | Technique |
|-------------|--------|-----------|
| SQL injection on login form | Initial Access | T1190 - Exploit Public-Facing Application |
| Hijacking a service account | Privilege Escalation | T1078 - Valid Accounts |
| Moving from web server to transaction server | Lateral Movement | T1021 - Remote Services |
| Executing the transfer script | Execution | T1059 - Command and Scripting Interpreter |

---

## Submitting Your Work

Bundle the following four items into a ZIP file named `<YourStudentID>_soc_lab.zip`:

| File | Where to find it |
|------|-----------------|
| `incident_report.txt` | Generated in the `student/` folder after running `analysis.py` |
| `analysis.py` | Your completed version in the `student/` folder |
| Splunk screenshots | One screenshot per Task 1.1 through 1.5 (5 minimum) |
| Phase 3 PDF report | Your written report |

Create the ZIP from the terminal:

```bash
zip -r <YourStudentID>_soc_lab.zip \
  student/incident_report.txt \
  student/analysis.py \
  screenshots/ \
  report.pdf
```

Submit via the course portal.

---

## Troubleshooting

### Docker daemon is not running

```bash
sudo systemctl start docker
sudo systemctl status docker
```

If Docker starts but stops immediately, check its logs:

```bash
sudo journalctl -u docker --no-pager | tail -30
```

### Permission denied when running docker commands

Add your user to the docker group and re-login:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

### Splunk never starts or stays on "Waiting..."

Check available memory - Splunk requires at least 2 GB of free RAM:

```bash
free -h
```

If memory is tight, close other applications and try again.

### Log generator exited with an error

Check what went wrong:

```bash
docker compose logs log-generator
```

Common cause: `STUDENT_SEED` in `.env` is not a plain integer. Open `.env` and make sure it looks like `STUDENT_SEED=1001` with no quotes or spaces.

### Logs not showing up in Splunk after 2 minutes

Check the generator completed successfully:

```bash
docker compose ps
```

The `log-generator` service should show `Exited (0)`. Then check Splunk's input monitoring:

```bash
docker compose logs splunk | grep -i "error\|warn\|monitor"
```

If nothing helps, wipe and restart:

```bash
docker compose down -v
docker compose up --build
```

The `-v` flag removes the Docker volume so logs are regenerated fresh from your seed.

### `python3: command not found`

Install Python:

```bash
sudo apt install -y python3   # Debian/Ubuntu/Kali
sudo dnf install -y python3   # Fedora/RHEL
```

### `ModuleNotFoundError` when running `analysis.py`

The script uses only the Python standard library - no `pip install` is needed. If you see this error, check your Python version:

```bash
python3 --version
```

It must be 3.10 or higher.

### Splunk password forgotten

```bash
docker compose exec splunk entrypoint.sh splunk edit user admin \
  -password NewPass123! -auth admin:OldPassword
```

Replace `OldPassword` with whatever you set in `.env`. If you cannot remember it at all:

```bash
docker compose rm -f splunk
docker compose up splunk -d
```

This recreates only the Splunk container. Your log volume is separate and will not be lost.

### Getting updates mid-exercise

```bash
git pull
```

Your `.env` and completed `analysis.py` are not tracked by Git and will not be overwritten.
