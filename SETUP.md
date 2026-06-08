# Instructor Setup Guide — FirstBank Nigeria SOC Training Lab

> **DISCLAIMER:** All data in this repository is entirely synthetic.
> This is an authorized cybersecurity training exercise only.

---

## Overview

Each student runs their own isolated Docker environment.  The log generator
uses a unique integer seed (`STUDENT_SEED`) so that every student's dataset
has different attacker IPs, timestamps, account numbers, and transfer amounts,
preventing answer sharing while keeping the scenario structure identical.

---

## Prerequisites (Instructor Workstation)

- Docker Desktop ≥ 4.x (for test-run validation)
- Python 3.10+
- Git + access to push to the course GitHub organisation

---

## Step 1 — Fork / Push to Course Repository

```bash
git clone <this-repo>
cd banking-soc-project
# Add your course GitHub remote:
git remote add course git@github.com:<your-org>/soc-lab-2026.git
git push course main
```

Students will clone from your course remote.

---

## Step 2 — Assign Seeds

Choose a unique integer seed for each student.  A simple scheme:

```python
# Example: use student ID hash
import hashlib
student_id = "STU-20260001"
seed = int(hashlib.sha256(student_id.encode()).hexdigest()[:8], 16) % 1_000_000
```

Or maintain a spreadsheet:

| Student | ID | Seed |
|---------|----|------|
| Adaobi Okafor | STU-001 | 84291 |
| Chidi Nwosu   | STU-002 | 57103 |
| …             | …       | …     |

Seeds need not be secret (the scenario structure is known), but keeping them
per-student prevents identical submissions.

Communicate seeds via the course LMS (one-per-student private message).

---

## Step 3 — Student Workflow

Students receive the repository URL and their seed.  They follow the
`student/README.md`:

```bash
git clone <course-repo-url>
cd banking-soc-project
cp .env.example .env
# Edit .env: set STUDENT_SEED and SPLUNK_PASSWORD
docker compose up --build
```

**Splunk Web:** http://localhost:8000 (admin / their chosen password)

Students must:
1. Complete Phase 1 (Splunk SPL queries + screenshots)
2. Complete Phase 2 (`student/analysis.py` → generates `incident_report.txt`)
3. Write Phase 3 report (PDF)

---

## Step 4 — Grading

### Validate with the answer key

For each student submission, regenerate the ground-truth data:

```bash
# In the repo root:
STUDENT_SEED=<student-seed> python data-generator/generate_logs.py
# This writes logs/ with that student's data.

# Run the answer key against a mock Splunk export (or the student's export):
python instructor/analysis_answer_key.py \
  --nessus  logs/nessus_scan.csv \
  --splunk  <student-submitted-splunk_export.csv> \
  --report  instructor/reference_report.txt
```

Compare `reference_report.txt` with the student's `incident_report.txt`.

### Key fields to validate (seed-specific)

Read `logs/scenario_manifest.json` for the canonical values:

```bash
cat logs/scenario_manifest.json
```

| Field to check | Source |
|----------------|--------|
| Attacker IP | `manifest["attacker_ip"]` |
| Entry-point host | `manifest["entry_point_host"]` |
| Transaction server | `manifest["txn_server_host"]` |
| Service account | `manifest["service_account"]` |

See `instructor/ANSWER_KEY.md` for SPL hints, scoring rubric, and MITRE ATT&CK
mapping guidance.

---

## Resource Requirements (Per Student)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM (Docker) | 3 GB | 4–6 GB |
| Disk | 5 GB | 10 GB |
| CPU cores | 2 | 4 |

Splunk Enterprise (free licence, ≤500 MB/day indexing) is sufficient.
The synthetic logs total < 2 MB per student.

Warn students: **on first start, Splunk may take 2–4 minutes** before the
Web UI becomes responsive.

---

## Updating the Python Skeleton Mid-Lab

If you need to push a fix to `student/analysis.py`:

```bash
# Edit student/analysis.py on your local main
git add student/analysis.py
git commit -m "fix: clarify parse_splunk_export docstring"
git push course main
```

Students run `git pull` to fetch the update.  Their code in the same file is
**not overwritten** (they add to existing TODOs rather than a separate file),
so remind them to `git stash` any local edits before pulling, then `git stash pop`.

---

## Troubleshooting

### Splunk container exits immediately

Check Docker memory.  The Splunk image requires ≥ 2 GB.  Increase in
Docker Desktop → Settings → Resources → Memory.

### Logs not indexed

```bash
docker compose logs splunk | grep -i "monitor\|input\|error"
```

Common cause: the `log-generator` container did not complete before Splunk
started.  Check:

```bash
docker compose ps
# log-generator should be Exited (0); any non-zero exit = generation error
docker compose logs log-generator
```

Re-run with:

```bash
docker compose down -v   # removes the logs volume
docker compose up --build
```

### Student lost their `.env`

They can recreate it from `.env.example` — remind them of their seed number.

### Splunk password forgotten

```bash
docker compose exec splunk entrypoint.sh splunk edit user admin -password NewPass123! -auth admin:OldPass
```

Or destroy and recreate the container (logs volume is separate and preserved):

```bash
docker compose stop splunk
docker compose rm splunk
docker compose up splunk -d
```

---

## Security Note

The Splunk container binds to `localhost:8000` only.  Students running on
shared lab machines should use distinct `SPLUNK_PASSWORD` values and note that
Docker port bindings are per-host; two students on the same machine must use
different host ports.  Edit `docker-compose.yml` ports section:

```yaml
ports:
  - "8001:8000"   # change left side per student on shared hosts
```
