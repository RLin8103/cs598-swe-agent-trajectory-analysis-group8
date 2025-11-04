# code.py
# ---------------------------------------------------------------------
# SWE-Agent Trajectory Analysis — Task 1 (Tab 1)
# Implements:
#  1) locate_reproduction_code(instance_id: str) -> list[int]
#  2) locate_search(instance_id: str) -> list[int]
#  3) locate_tool_use(instance_id: str) -> dict[str, int]
#
# Logging:
#   locate_reproduction_code() -> "locate_reproduction_code.log"
#   locate_search()            -> "locate_search.log"
#   locate_tool_use()          -> "locate_tool_use.log"
#
# Environment:
#   SWE_TRAJ_DIR  (optional) base directory of trajectory files
#
# Notes:
# - Uses only Python stdlib. No external dependencies.
# - Robust to SWE-Agent JSON variants:
#     * list of steps
#     * {"trajectory": [...]}
#     * {"steps": [...]}
#     * NDJSON (one JSON object per line)
# - Step indexing:
#     If a step number field exists ("step", "index", "idx"), we use it.
#     Otherwise we assign 1-based indices in file order.
# ---------------------------------------------------------------------

from __future__ import annotations
import os
import sys
import json
import argparse
import re
from typing import Any, Dict, Iterable, List, Tuple

# -------------------------
# Configuration
# -------------------------
# Layout: ./trajs/{sweagent_claud4,sweagent_lm}/<traj_id_dir>/*.traj
BASE_DIR = os.environ.get("SWE_TRAJ_DIR", "./trajs")

REPRO_KEYWORDS = re.compile(r"(reproduce|repro|debug|test)", re.IGNORECASE)
REPRO_THOUGHT_HINTS = re.compile(
    r"(create|write|add|build).*(repro(duce)?|debug).*"
    r"|minimal.*repro|reproduction.*test|failing.*test|unit\s*test",
    re.IGNORECASE,
)

# Add more search/navigation tools commonly seen in dumps
SEARCH_TOOL_NAMES = {
    "find_file", "search_file", "search_dir", "ripgrep", "rg",
    "list_dir", "list_files", "open_file", "view_file", "read_file",
    "glob", "walk", "search", "grep_file",
}

# Expand shell/navigation heads (POSIX + Windows)
SHELL_SEARCH_CMDS = {
    # POSIX
    "find", "grep", "rg", "ag", "fd", "ls", "cd", "cat", "tree", "git", "sed", "awk",
    # Windows
    "findstr", "where", "dir", "type",
    # git helpers
    "git-grep", "gitls", "git-ls-files",
}

KNOWN_TOOLS = {
    "view", "create", "str_replace", "insert", "undo_edit", "apply_patch",
    "bash", "terminal", "exec", "run", "open", "edit", "write_file",
}

# -------------------------
# File & JSON helpers
# -------------------------

def _candidate_files_for_id(instance_id: str) -> List[str]:
    """
    Return possible trajectory file paths for an instance ID.

    Supports:
      - extensions: .traj, .json, .jsonl, .ndjson
      - matching by full ID and by problem slug (text after '@')
      - recursive scan under BASE_DIR
    """
    exts = (".traj", ".json", ".jsonl", ".ndjson")
    paths: List[str] = []

    problem = instance_id.split("@")[-1] if "@" in instance_id else instance_id

    for base in (instance_id, problem):
        for ext in exts:
            p = os.path.join(BASE_DIR, f"{base}{ext}")
            if os.path.isfile(p):
                paths.append(p)

    if os.path.isdir(BASE_DIR):
        for root, _, files in os.walk(BASE_DIR):
            for fn in files:
                if not fn.endswith(exts):
                    continue
                if problem in fn or instance_id in fn:
                    paths.append(os.path.join(root, fn))

    seen, uniq = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p); uniq.append(p)
    return uniq


def _read_json_any(path: str) -> List[Dict[str, Any]]:
    """
    Read trajectory that may be:
      - a list[step]
      - {"trajectory": list[step]} or {"steps": list[step]}
      - NDJSON (one JSON object per line)
    Return a list of step dicts.
    """
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read().strip()

    if not txt:
        return []

    try:
        data = json.loads(txt)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            if isinstance(data.get("trajectory"), list):
                return data["trajectory"]
            if isinstance(data.get("steps"), list):
                return data["steps"]
            return [data]
    except json.JSONDecodeError:
        pass

    steps: List[Dict[str, Any]] = []
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                steps.append(obj)
        except json.JSONDecodeError:
            continue
    return steps


def _load_trajectory(instance_id: str) -> Tuple[List[Dict[str, Any]], str]:
    cands = _candidate_files_for_id(instance_id)
    if not cands:
        raise FileNotFoundError(f"No trajectory file found for ID '{instance_id}' in '{BASE_DIR}'.")
    for path in cands:
        steps = _read_json_any(path)
        if steps:
            return steps, path
    raise FileNotFoundError(f"Found candidate files for '{instance_id}' but none contained steps.")


def _iter_steps_with_index(steps: List[Dict[str, Any]]) -> Iterable[Tuple[int, Dict[str, Any]]]:
    """Yield (step_index, step_dict). Prefer explicit index, else 1-based enumeration."""
    def try_get_idx(s: Dict[str, Any]) -> int | None:
        for k in ("step", "index", "idx"):
            if k in s:
                try:
                    return int(s[k])
                except Exception:
                    pass
        return None

    extracted: List[Tuple[int, Dict[str, Any]]] = []
    explicit = True
    for s in steps:
        idx = try_get_idx(s)
        if idx is None:
            explicit = False
            break
        extracted.append((idx, s))

    if explicit and extracted:
        extracted.sort(key=lambda t: t[0])
        for t in extracted:
            yield t
        return

    for i, s in enumerate(steps, start=1):
        yield i, s

# -------------------------
# Field extraction helpers
# -------------------------

def _get_action_name(step: Dict[str, Any]) -> str:
    for k in ("action", "tool", "command", "name", "tool_name", "type"):
        v = step.get(k)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, dict):
            n = v.get("name") or v.get("tool") or v.get("type")
            if isinstance(n, str) and n:
                return n
    return ""


def _get_action_obj(step: Dict[str, Any]) -> Dict[str, Any]:
    for k in ("action", "tool", "command"):
        v = step.get(k)
        if isinstance(v, dict):
            return v
    return {}


def _get_args(step: Dict[str, Any]) -> Dict[str, Any]:
    act = _get_action_obj(step)
    for k in ("args", "arguments", "params", "parameters"):
        v = act.get(k) if act else step.get(k)
        if isinstance(v, dict):
            return v
    return {}


def _get_command_string(step: Dict[str, Any]) -> str:
    """
    Extract a shell/terminal command string if present. Covers common single-string
    fields, args-based fields, list-of-commands, and falls back to scanning messages.
    """
    act = _get_action_obj(step)

    for k in ("cmd", "command", "shell", "bash", "run", "input"):
        v = act.get(k) if act else step.get(k)
        if isinstance(v, str):
            return v.strip()

    args = _get_args(step)
    for k in ("cmdline", "commandline"):
        v = args.get(k)
        if isinstance(v, str):
            return v.strip()

    for k in ("commands", "cmds"):
        v = args.get(k) or (act.get(k) if act else None)
        if isinstance(v, list) and v and isinstance(v[0], str):
            return " && ".join(v).strip()

    for k in ("content", "message", "assistant_message"):
        v = step.get(k)
        if isinstance(v, str) and any(tok in v for tok in (
            "grep", "find", "rg", "ls", "cd", "cat", "tree", "findstr", "dir", "type"
        )):
            return v.strip()

    return ""


def _get_filename_from_step(step: Dict[str, Any]) -> str:
    args = _get_args(step)
    candidates: List[str] = []
    for k in ("filename", "path", "filepath", "file_path", "target", "dst", "dst_path"):
        v = args.get(k)
        if isinstance(v, str):
            candidates.append(v)
    file_obj = args.get("file")
    if isinstance(file_obj, dict):
        for k in ("name", "path"):
            v = file_obj.get(k)
            if isinstance(v, str):
                candidates.append(v)
    for k in ("filename", "path"):
        v = step.get(k)
        if isinstance(v, str):
            candidates.append(v)

    for c in candidates:
        if "/" in c or "." in c or c.endswith(".py") or c.endswith(".txt"):
            return c
    return candidates[0] if candidates else ""


def _get_thought(step: Dict[str, Any]) -> str:
    for k in ("thought", "thoughts", "reasoning", "rationale", "plan", "analysis"):
        v = step.get(k)
        if isinstance(v, str):
            return v
    for k in ("assistant_thought", "assistant_comment", "assistant_message"):
        v = step.get(k)
        if isinstance(v, str):
            return v
    return ""

# -------------------------
# Heuristics
# -------------------------

def _looks_like_repro_file(name: str) -> bool:
    return bool(name and REPRO_KEYWORDS.search(name))


def _looks_like_repro_thought(thought: str) -> bool:
    return bool(thought and REPRO_THOUGHT_HINTS.search(thought))


def _is_search_like_action(action_name: str) -> bool:
    return (action_name or "").strip().lower() in SEARCH_TOOL_NAMES


def _is_shell_search(cmd: str) -> bool:
    if not cmd:
        return False
    toks = cmd.strip().split()
    if not toks:
        return False
    head = toks[0]
    if head == "git" and len(toks) >= 2 and toks[1] == "grep":
        return True
    return head in SHELL_SEARCH_CMDS


def _shell_head(cmd: str) -> str:
    if not cmd:
        return ""
    toks = cmd.strip().split()
    if not toks:
        return ""
    if toks[0] == "git" and len(toks) >= 2 and toks[1] == "grep":
        return "git-grep"
    return toks[0]

# -------------------------
# Logging helpers
# -------------------------

def _append_log(logfile: str, instance_id: str, payload: Any) -> None:
    with open(logfile, "a", encoding="utf-8") as f:
        f.write("\n" + "-" * 72 + "\n")
        f.write(f"ID: {instance_id}\n")
        f.write(json.dumps(payload, indent=2, ensure_ascii=False))
        f.write("\n")

# -------------------------
# Required public APIs
# -------------------------

def locate_reproduction_code(instance_id: str) -> List[int]:
    steps, _ = _load_trajectory(instance_id)
    hits: List[int] = []

    for idx, step in _iter_steps_with_index(steps):
        action = _get_action_name(step).lower()
        thought = _get_thought(step)
        fname = _get_filename_from_step(step)

        is_editor_action = action in {"create", "insert", "str_replace", "write_file", "apply_patch", "edit"}
        looks_repro = _looks_like_repro_file(fname) or _looks_like_repro_thought(thought)

        if is_editor_action and looks_repro:
            hits.append(idx)
            continue
        if is_editor_action and fname and re.search(r"test.*\.py$", fname, re.IGNORECASE):
            hits.append(idx)
            continue
        if "create" in action and _looks_like_repro_thought(thought):
            hits.append(idx)

    _append_log("locate_reproduction_code.log", instance_id, hits)
    return hits


def locate_search(instance_id: str) -> List[int]:
    steps, _ = _load_trajectory(instance_id)
    hits: List[int] = []
    prev_was_search = False

    for idx, step in _iter_steps_with_index(steps):
        action = _get_action_name(step).strip().lower()
        cmd = _get_command_string(step)

        this_is_search = False
        if _is_search_like_action(action):
            this_is_search = True
        if _is_shell_search(cmd):
            this_is_search = True
        if action == "view" and prev_was_search:
            this_is_search = True

        # Thought-based fallback (helps when tools summarize searches)
        if not this_is_search:
            thought = _get_thought(step).lower()
            if any(w in thought for w in ("search", "grep", "find in", "look for", "scan directory", "navigate to", "list files")):
                this_is_search = True

        if this_is_search:
            hits.append(idx)
        prev_was_search = this_is_search

    _append_log("locate_search.log", instance_id, hits)
    return hits


def locate_tool_use(instance_id: str) -> Dict[str, int]:
    steps, _ = _load_trajectory(instance_id)
    counts: Dict[str, int] = {}

    def bump(key: str) -> None:
        if key:
            counts[key] = counts.get(key, 0) + 1

    for _, step in _iter_steps_with_index(steps):
        action = _get_action_name(step).strip().lower()
        if action:
            bump(action)
        cmd = _get_command_string(step)
        head = _shell_head(cmd)
        if head:
            bump(f"shell:{head}")

    _append_log("locate_tool_use.log", instance_id, counts)
    return counts

# -------------------------
# Minimal CLI
# -------------------------

def _run_cli() -> None:
    parser = argparse.ArgumentParser(
        description="SWE-Agent trajectory analysis (Task 1). Set SWE_TRAJ_DIR or keep ./trajs."
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("instance_id", nargs="?", help="Full ID (e.g., 20250522_...@django__django-11820)")
        sp.add_argument("--ids-file", help="Optional file with one instance_id per line.")
        sp.add_argument("--print-only", action="store_true", help="Print results without logging.")

    add_common(subparsers.add_parser("locate_reproduction_code"))
    add_common(subparsers.add_parser("locate_search"))
    add_common(subparsers.add_parser("locate_tool_use"))

    args = parser.parse_args()

    ids: List[str] = []
    if args.instance_id:
        ids.append(args.instance_id)
    if args.ids_file:
        with open(args.ids_file, "r", encoding="utf-8") as f:
            ids += [ln.strip() for ln in f if ln.strip()]

    if not ids:
        print("ERROR: Provide an instance_id or --ids-file", file=sys.stderr)
        sys.exit(2)

    for iid in ids:
        try:
            if args.cmd == "locate_reproduction_code":
                out = locate_reproduction_code(iid)
                if args.print_only:
                    print(json.dumps({"id": iid, "steps": out}, indent=2))
            elif args.cmd == "locate_search":
                out = locate_search(iid)
                if args.print_only:
                    print(json.dumps({"id": iid, "steps": out}, indent=2))
            elif args.cmd == "locate_tool_use":
                out = locate_tool_use(iid)
                if args.print_only:
                    print(json.dumps({"id": iid, "counts": out}, indent=2))
        except FileNotFoundError as e:
            msg = {"error": str(e)}
            if args.cmd == "locate_reproduction_code":
                _append_log("locate_reproduction_code.log", iid, msg)
            elif args.cmd == "locate_search":
                _append_log("locate_search.log", iid, msg)
            elif args.cmd == "locate_tool_use":
                _append_log("locate_tool_use.log", iid, msg)
            print(f"[WARN] {e}", file=sys.stderr)

if __name__ == "__main__":
    _run_cli()
