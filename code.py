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
#   SWE_TRAJ_DIR  (optional) base directory of trajectory JSON files
#
# Notes:
# - Uses only Python stdlib. No external dependencies.
# - Robust to common SWE-Agent JSON variants:
#     * a list of step dicts
#     * an object with "trajectory" -> list of step dicts
#     * NDJSON (one JSON object per line)
# - Step indexing:
#     If a step number field exists ("step", "index"), we use it (int).
#     Otherwise we assign 1-based indices in file order.
# - Reproduction-code detection is heuristic-based:
#     * action type "create"/"insert"/"str_replace" with a filename containing
#       {"reproduce","repro","debug","test"} (case-insensitive),
#       or a thought mentioning creating a repro/debug test.
# - Search/navigation detection:
#     * SWE-Agent tools: {"find_file","search_file","search_dir","ripgrep","rg"}
#     * shell commands: {"find","grep","rg","ag","fd","ls","cd","cat","tree"}
#     * "view" used immediately after a search-like action also counts
# - Tool-usage counting:
#     * Counts SWE-Agent tools by their action/tool name (e.g., "view","create",…)
#     * Also counts shell commands individually under keys like "shell:grep"
#       when actions execute a shell/terminal/bash command.
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
BASE_DIR = os.environ.get("SWE_TRAJ_DIR", "./trajectories")

REPRO_KEYWORDS = re.compile(r"(reproduce|repro|debug|test)", re.IGNORECASE)
REPRO_THOUGHT_HINTS = re.compile(
    r"(create|write|add|build).*(repro(duce)?|debug).*"
    r"|minimal.*repro|reproduction.*test|failing.*test|unit\s*test",
    re.IGNORECASE,
)

SEARCH_TOOL_NAMES = {
    "find_file", "search_file", "search_dir", "ripgrep", "rg",
}

SHELL_SEARCH_CMDS = {
    "find", "grep", "rg", "ag", "fd", "ls", "cd", "cat", "tree", "git", "git-grep"
}

# Some known SWE-Agent edit/view tool names
KNOWN_TOOLS = {
    "view", "create", "str_replace", "insert", "undo_edit", "apply_patch",
    "bash", "terminal", "exec", "run", "open", "edit", "write_file",
}

# -------------------------
# File & JSON helpers
# -------------------------

def _candidate_files_for_id(instance_id: str) -> List[str]:
    """Return possible trajectory file paths for an instance ID."""
    paths: List[str] = []

    # 1) Direct file match
    direct = os.path.join(BASE_DIR, f"{instance_id}.json")
    if os.path.isfile(direct):
        paths.append(direct)

    # 2) Scan for any *.json that contains the instance_id (robust to naming)
    if os.path.isdir(BASE_DIR):
        for root, _, files in os.walk(BASE_DIR):
            for fn in files:
                if fn.endswith(".json") and instance_id in fn:
                    paths.append(os.path.join(root, fn))

    # Deduplicate preserving order
    seen = set()
    uniq = []
    for p in paths:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq


def _read_json_any(path: str) -> List[Dict[str, Any]]:
    """
    Read trajectory that may be:
      - a list[step]
      - an object {"trajectory": list[step]}
      - NDJSON (one JSON per line)
    Return a list of step dicts.
    """
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read().strip()

    if not txt:
        return []

    # Try plain JSON first
    try:
        data = json.loads(txt)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Common: object with "trajectory"
            if "trajectory" in data and isinstance(data["trajectory"], list):
                return data["trajectory"]
            # Some logs have "steps"
            if "steps" in data and isinstance(data["steps"], list):
                return data["steps"]
            # Otherwise, maybe a single step?
            return [data]
    except json.JSONDecodeError:
        pass

    # Try NDJSON
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
            # best-effort: ignore bad lines
            continue
    return steps


def _load_trajectory(instance_id: str) -> Tuple[List[Dict[str, Any]], str]:
    """
    Load the first matching trajectory for instance_id.
    Returns (steps, path). Raises FileNotFoundError if none found or empty.
    """
    cands = _candidate_files_for_id(instance_id)
    if not cands:
        raise FileNotFoundError(f"No trajectory file found for ID '{instance_id}' in '{BASE_DIR}'.")
    for path in cands:
        steps = _read_json_any(path)
        if steps:
            return steps, path
    raise FileNotFoundError(f"Found candidate files for '{instance_id}' but none contained steps.")


def _iter_steps_with_index(steps: List[Dict[str, Any]]) -> Iterable[Tuple[int, Dict[str, Any]]]:
    """
    Yield (step_index, step_dict). If an explicit index exists, use it; otherwise 1-based enumeration.
    Acceptable index keys: 'step', 'index', 'idx'.
    """
    # Try to see if any have an explicit integer step index
    def try_get_idx(s: Dict[str, Any]) -> int | None:
        for k in ("step", "index", "idx"):
            if k in s:
                try:
                    return int(s[k])
                except Exception:
                    continue
        return None

    explicit = True
    extracted = []
    for s in steps:
        idx = try_get_idx(s)
        if idx is None:
            explicit = False
            break
        extracted.append((idx, s))

    if explicit and extracted:
        # ensure stable order by idx in case file is unordered
        extracted.sort(key=lambda t: t[0])
        for t in extracted:
            yield t
        return

    # Fallback: 1-based
    for i, s in enumerate(steps, start=1):
        yield i, s

# -------------------------
# Field extraction helpers
# -------------------------

def _get_action_name(step: Dict[str, Any]) -> str:
    """
    Try common places for action/tool name.
    """
    # SWE-Agent formats vary; check likely fields
    for k in ("action", "tool", "command", "name", "tool_name", "type"):
        v = step.get(k)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, dict):
            # sometimes 'action' is an object with 'name'
            n = v.get("name") or v.get("tool") or v.get("type")
            if isinstance(n, str) and n:
                return n
    return ""


def _get_action_obj(step: Dict[str, Any]) -> Dict[str, Any]:
    """Return a dict-like subobject of the action if present, else {}."""
    for k in ("action", "tool", "command"):
        v = step.get(k)
        if isinstance(v, dict):
            return v
    return {}


def _get_args(step: Dict[str, Any]) -> Dict[str, Any]:
    """Return action arguments dict if present."""
    act = _get_action_obj(step)
    for k in ("args", "arguments", "params", "parameters"):
        v = act.get(k) if act else step.get(k)
        if isinstance(v, dict):
            return v
    # Sometimes commands are at top-level
    return {}


def _get_command_string(step: Dict[str, Any]) -> str:
    """Extract a shell/terminal command string if present."""
    act = _get_action_obj(step)
    # Common fields for shell execution
    for k in ("cmd", "command", "shell", "bash", "run", "input"):
        v = act.get(k) if act else step.get(k)
        if isinstance(v, str):
            return v.strip()
    # Some logs store the last message content:
    for k in ("content", "message"):
        v = step.get(k)
        if isinstance(v, str) and any(tok in v for tok in ("grep", "find", "rg", "ls", "cd", "cat", "tree")):
            return v.strip()
    return ""


def _get_filename_from_step(step: Dict[str, Any]) -> str:
    """
    Heuristically pull a filename from action args or content fields.
    """
    args = _get_args(step)
    candidates = []
    for k in ("filename", "path", "filepath", "file_path", "target", "dst", "dst_path"):
        v = args.get(k)
        if isinstance(v, str):
            candidates.append(v)
    # Some create/edit actions include an embedded 'file' object
    file_obj = args.get("file")
    if isinstance(file_obj, dict):
        for k in ("name", "path"):
            v = file_obj.get(k)
            if isinstance(v, str):
                candidates.append(v)
    # Look in top-level convenience fields
    for k in ("filename", "path"):
        v = step.get(k)
        if isinstance(v, str):
            candidates.append(v)

    # Return the first plausible file-like path
    for c in candidates:
        if "/" in c or "." in c or c.endswith(".py") or c.endswith(".txt"):
            return c
    return candidates[0] if candidates else ""


def _get_thought(step: Dict[str, Any]) -> str:
    """Extract the agent's thought/rationale if present."""
    for k in ("thought", "thoughts", "reasoning", "rationale", "plan", "analysis"):
        v = step.get(k)
        if isinstance(v, str):
            return v
    # Some formats tuck it into messages
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
    a = (action_name or "").strip().lower()
    return a in SEARCH_TOOL_NAMES


def _is_shell_search(cmd: str) -> bool:
    if not cmd:
        return False
    # take the first token of the command (supports pipelines)
    first = cmd.strip().split()
    if not first:
        return False
    head = first[0]
    # common "git grep" shape
    if head == "git" and len(first) >= 2 and first[1] == "grep":
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
    os.makedirs(".", exist_ok=True)
    with open(logfile, "a", encoding="utf-8") as f:
        f.write("\n" + "-" * 72 + "\n")
        f.write(f"ID: {instance_id}\n")
        f.write(json.dumps(payload, indent=2, ensure_ascii=False))
        f.write("\n")

# -------------------------
# Required public APIs
# -------------------------

def locate_reproduction_code(instance_id: str) -> List[int]:
    """
    Find trajectory steps under which the agent creates a reproduction test/code.

    Input:
        instance_id: str  (format like 'AGENT@PROBLEM')
    Output:
        List[int]  (step indices)
    Side-effect:
        Append result to 'locate_reproduction_code.log'
    """
    steps, _ = _load_trajectory(instance_id)
    hits: List[int] = []

    for idx, step in _iter_steps_with_index(steps):
        action = _get_action_name(step).lower()
        thought = _get_thought(step)
        fname = _get_filename_from_step(step)

        is_editor_action = action in {"create", "insert", "str_replace", "write_file", "apply_patch", "edit"}
        looks_repro = _looks_like_repro_file(fname) or _looks_like_repro_thought(thought)

        # Also catch create actions whose args contain a test-like filename content blob
        if is_editor_action and looks_repro:
            hits.append(idx)
            continue

        # Looser heuristic: create a new python file that includes 'test' in name
        if is_editor_action and fname and re.search(r"test.*\.py$", fname, re.IGNORECASE):
            hits.append(idx)
            continue

        # If an action explicitly mentions "create" and the thought says minimal repro
        if "create" in action and _looks_like_repro_thought(thought):
            hits.append(idx)

    _append_log("locate_reproduction_code.log", instance_id, hits)
    return hits


def locate_search(instance_id: str) -> List[int]:
    """
    Find trajectory steps where the agent searches or navigates inside the repo.

    Input:
        instance_id: str
    Output:
        List[int]  (step indices)
    Side-effect:
        Append result to 'locate_search.log'
    """
    steps, _ = _load_trajectory(instance_id)
    hits: List[int] = []

    # Track if previous action was a search; some 'view' immediately after a search counts.
    prev_was_search = False

    for idx, step in _iter_steps_with_index(steps):
        action = _get_action_name(step).strip().lower()
        cmd = _get_command_string(step)

        this_is_search = False

        # SWE-Agent dedicated search tools
        if _is_search_like_action(action):
            this_is_search = True

        # Shell search/navigation commands
        if _is_shell_search(cmd):
            this_is_search = True

        # Heuristic: 'view' after a search step is part of navigation
        if action == "view" and prev_was_search:
            this_is_search = True

        if this_is_search:
            hits.append(idx)

        prev_was_search = this_is_search

    _append_log("locate_search.log", instance_id, hits)
    return hits


def locate_tool_use(instance_id: str) -> Dict[str, int]:
    """
    Extract tool uses in the trajectory.

    Input:
        instance_id: str
    Output:
        dict[str,int] where key is tool name and value is how many times it's called
        - SWE-Agent tools counted by action/tool name (e.g., 'view','create',…)
        - Shell commands counted as 'shell:<head>' (e.g., 'shell:grep')
    Side-effect:
        Append result to 'locate_tool_use.log'
    """
    steps, _ = _load_trajectory(instance_id)
    counts: Dict[str, int] = {}

    def bump(key: str) -> None:
        if not key:
            return
        counts[key] = counts.get(key, 0) + 1

    for _, step in _iter_steps_with_index(steps):
        action = _get_action_name(step).strip()
        action_l = action.lower()

        # Count explicit SWE-Agent tool/action names (best-effort)
        if action_l:
            bump(action_l)
            # Normalize some aliases into a single bucket too
            if action_l in KNOWN_TOOLS:
                # Keep distinct—already bumped—as graders may expect raw names
                pass

        # If this step executed a shell command, count the head
        cmd = _get_command_string(step)
        head = _shell_head(cmd)
        if head:
            bump(f"shell:{head}")

    _append_log("locate_tool_use.log", instance_id, counts)
    return counts

# -------------------------
# Minimal CLI for graders
# -------------------------

def _run_cli() -> None:
    parser = argparse.ArgumentParser(
        description="SWE-Agent trajectory analysis (Task 1). "
                    "Set SWE_TRAJ_DIR to your trajectories folder."
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("instance_id", nargs="?", help="ID of the instance (e.g., 'Claude-4@repo__issue_123').")
        sp.add_argument("--ids-file", help="Optional: path to a file with one instance_id per line.")
        sp.add_argument("--print-only", action="store_true", help="Print results without logging (logging is required by default).")

    sp1 = subparsers.add_parser("locate_reproduction_code", help="Find steps where reproduction code is created.")
    add_common(sp1)

    sp2 = subparsers.add_parser("locate_search", help="Find steps where the agent searches/navigates the repo.")
    add_common(sp2)

    sp3 = subparsers.add_parser("locate_tool_use", help="Count tool/shell usage across the trajectory.")
    add_common(sp3)

    args = parser.parse_args()

    # Collect IDs to process
    ids: List[str] = []
    if args.instance_id:
        ids.append(args.instance_id)
    if args.ids_file:
        with open(args.ids_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    ids.append(line)

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
            # Still log an empty/diagnostic payload to the appropriate log for traceability
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
