# SWE-Agent Trajectory Analysis — Group 8

This repo contains **Task 1 (Tab 1)** scripts to analyze SWE-Agent trajectories and generate three logs.

## Prerequisites
- Python 3.8+
- Place your trajectory dumps under `./trajs/` as:
```
trajs/
  sweagent_claud4/ .../*.traj (+ optional .config/.pred/.patch)
  sweagent_lm/    .../*.traj
```
- Files at repo root:
```
code.py
assigned_ids.txt   # your 20 IDs, one per line
```

> `code.py` defaults to `./trajs`, so you usually don’t need to set any env vars.

---

## Run (Windows PowerShell)
From the repo root:
```powershell
# Optional: set env var (only if you changed the folder)
$env:SWE_TRAJ_DIR = ".	rajs"

python code.py locate_reproduction_code --ids-file assigned_ids.txt
python code.py locate_search            --ids-file assigned_ids.txt
python code.py locate_tool_use          --ids-file assigned_ids.txt
```

## Run (Windows CMD)
```cmd
REM Optional: set env var
set SWE_TRAJ_DIR=.	rajs

python code.py locate_reproduction_code --ids-file assigned_ids.txt
python code.py locate_search            --ids-file assigned_ids.txt
python code.py locate_tool_use          --ids-file assigned_ids.txt
```

## Run (macOS/Linux/Git Bash/WSL)
```bash
# Optional: set env var
export SWE_TRAJ_DIR=./trajs

python code.py locate_reproduction_code --ids-file assigned_ids.txt
python code.py locate_search            --ids-file assigned_ids.txt
python code.py locate_tool_use          --ids-file assigned_ids.txt
```

---

## What gets created
These files are written to the repo root (appended per ID):
- `locate_reproduction_code.log`
- `locate_search.log`
- `locate_tool_use.log`

Each section starts with the ID, for example:
```
------------------------------------------------------------------------
ID: 20250522_sweagent_claude-4-sonnet-20250514@django__django-11820
[2, 7, 15]
```

For `locate_tool_use`, the payload is a JSON dictionary of tool counts.

---

## Single-ID examples
```powershell
python code.py locate_reproduction_code "20250522_sweagent_claude-4-sonnet-20250514@django__django-11820"
python code.py locate_search            "20250522_sweagent_claude-4-sonnet-20250514@sympy__sympy-17318"
python code.py locate_tool_use          "20250522_sweagent_claude-4-sonnet-20250514@matplotlib__matplotlib-21568"
```

## Print-only mode (no file writes)
```powershell
python code.py locate_search "20250522_sweagent_claude-4-sonnet-20250514@django__django-14404" --print-only
```

---

## Troubleshooting
- **No trajectory file found**: ensure the filename contains the **problem slug** (text after `@` in the ID), and that files are under `./trajs` (or set `SWE_TRAJ_DIR`). The script supports `.traj`, `.json`, `.jsonl`, `.ndjson` and scans recursively.
- To start fresh, delete the three `.log` files and re-run.

---

## Submission (what to zip)
Include only these at the top level of your zip (no subfolders):
```
code.py
assigned_ids.txt
locate_reproduction_code.log
locate_search.log
locate_tool_use.log
```
