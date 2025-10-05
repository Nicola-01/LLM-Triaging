#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evaluation.py — Separated evaluation pipeline (Planner + Implementer)

This script performs a two-stage evaluation, independent from the analysis phase:

1) FILTER: From a provided list of vulnerability assessments (JSON), identify which ones are
   likely exploitable (as opposed to mere crash conditions).
2) EXPLOIT LOOP: For each selected candidate, orchestrate two LLM agents:
   - EXPLOIT PLANNER (with Jadx + Ghidra MCP toolsets): drafts a concrete, minimal plan
     to reproduce/exploit the behaviour using realistic app entrypoints and observable success criteria.
   - EXPLOIT IMPLEMENTER: generates a single self-contained Python PoC script that uses adb/am/logcat,
     runs it, and if it fails, iteratively self-repairs based on the observed output/errors until either
     success or iteration limit.

The planner can optionally leverage a Call Sequence (CS) JSON file to understand app flows.

CLI
---
python3 evaluation.py APP.apk CS.json DEVICE_SERIAL \
  --assessments assessments.json \
  -m MODEL_NAME \
  --max-iters 3 \
  --eval-timeout 120 \
  -v -d \
  -o evaluation_report.json

Environment (required):
  - LLM_API_KEY
  - GHIDRA_INSTALL_DIR (e.g., /snap/ghidra/current/ghidra_11.4_PUBLIC)
  - JADX_MCP_DIR (directory containing `jadx_mcp_server.py`)

Notes:
- We assume adb is in PATH and device can run with root (`adb root`) if necessary.
- This script does not modify the existing analysis modules; it imports MCP wiring and agent factory.
"""

from __future__ import annotations
import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

# Project-local imports (do not change existing modules)

from utils import *
from MCPs.ollamaLocal import get_agent
from MCPs.jadxMCP import make_jadx_server
from MCPs.ghidraMCP import make_ghidra_server


# -------------------- Prompts (kept local to evaluation) --------------------

PLANNER_SYSTEM_PROMPT = """
You are the EXPLOIT PLANNER Agent.
Goal: given a fuzzing-derived crash context and access to Jadx/Ghidra MCP tools,
draft a concrete, minimal PLAN to exercise the same underlying bug in a realistic way.

Context / constraints:
- Crash logs come from an external fuzzing pipeline (e.g., AFL++ with a JNI harness). They can be noisy or partial.
- "Vulnerability" means an exploitable behaviour (information disclosure, arbitrary read/write, RCE, privilege escalation, sandbox escape, or security policy bypass), not a mere crash.
- Use ONLY information available from MCP tools (Jadx/Ghidra) and the provided JSON inputs. If unknown -> null. Do NOT guess.
- Prefer app-driven inputs (Android Intents/extras, files, ContentProvider URIs) over debugger tricks. JNI-only paths are allowed if that is the only realistic entry.
- Make your output self-contained for the IMPLEMENTER. Do not require interactive input or waiting.

Your PLAN must be a JSON object with fields:
- entrypoint: string|null  (Activity/Service/Broadcast/Provider component name, or 'direct JNI')
- preconditions: string[]  (permissions, files on device, account/session state) — empty if unknown
- steps: string[]          (ordered, concrete actions an adb-based script can perform)
- payload: string|null     (payload spec; hex/base64 or short textual description if simple)
- success_criteria: { "regex": string }[]  (regex list for logcat/process output to confirm success)
- notes: string[]          (safety reminders, assumptions)

Respond ONLY with the JSON object, no prose outside JSON.
If evidence is weak, still produce a best-effort plan with nulls and conservative steps.
"""

IMPLEMENTER_SYSTEM_PROMPT = """
You are the EXPLOIT IMPLEMENTER Agent.
Goal: given an Exploit Plan (JSON), produce a single, self-contained Python 3 script that:
- Accepts: --device <serial> and --timeout <seconds>
- Uses only Python stdlib + adb/am/logcat (invoked via subprocess)
- Prepares the device (root/remount if available), pushes payloads, executes the plan's steps, tails logcat
- Treats the plan's success_criteria as regex to detect success
- Prints EXACTLY 'EXPLOIT_SUCCESS' on success, otherwise 'EXPLOIT_FAIL'
- Exits with code 0 on success, non-zero on failure

Rules (do not block):
- Never ask for more info; never pause; always return the FULL script.
- If the plan lacks some fields, fail fast with a clear message in stdout but still provide the FULL runnable script.
- Do NOT import non-stdlib libraries.
- Do NOT write partial code; always output the entire script in one shot.

Output ONLY the Python source code (no backticks, no extra commentary).
"""

# -------------------- Models --------------------



class SuccessCriterion(BaseModel):
    regex: str

class ExploitPlan(BaseModel):
    entrypoint: Optional[str] = None
    preconditions: List[str] = Field(default_factory=list)
    steps: List[str] = Field(default_factory=list)
    payload: Optional[str] = None
    success_criteria: List[SuccessCriterion] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)

# -------------------- APK helpers (stand-alone) --------------------


def find_relevant_libs(so_paths: List[Path], tokens: List[str], max_libs: int = 5) -> List[Path]:
    """Rank libraries by presence of token symbols or strings; return top-N."""
    ranks: Dict[Path, int] = {}
    for so in so_paths:
        score = 0
        # nm / llvm-nm
        try:
            nm = shutil.which("nm") or shutil.which("llvm-nm")
            if nm:
                cp = subprocess.run([nm, "-D", str(so)], capture_output=True, text=True, timeout=5)
                out = (cp.stdout or "") + "\n" + (cp.stderr or "")
                for t in tokens:
                    if t and t in out:
                        score += 3
        except Exception:
            pass
        # strings fallback
        try:
            strings = shutil.which("strings")
            if strings:
                cp = subprocess.run([strings, "-a", str(so)], capture_output=True, text=True, timeout=5)
                out = cp.stdout or ""
                for t in tokens:
                    if t and re.search(re.escape(t), out, flags=re.IGNORECASE):
                        score += 1
        except Exception:
            pass
        if score > 0:
            ranks[so] = score
    ranked = sorted(ranks.items(), key=lambda kv: kv[1], reverse=True)
    return [p for p, _ in ranked[:max_libs]]

# -------------------- Stage 1: Filter exploitable candidates --------------------

HIGH_RISK_CWE = {"CWE-787","CWE-416","CWE-119","CWE-190","CWE-20","CWE-476","CWE-362","CWE-78","CWE-121","CWE-122"}
KEYWORDS_EXPLOITABLE = [
    "oob", "out-of-bounds", "overflow", "underflow", "uaf", "use-after-free",
    "double free", "arbitrary write", "arbitrary read", "format string",
    "code execution", "rce", "privilege", "info leak", "memory corruption",
    "stack overflow", "heap overflow", "integer overflow", "race condition"
]
CLASSES_EXPLOITABLE = {"OOB-Read","OOB-Write","UAF","Integer-Overflow","Double-Free","Heap-Overflow","Stack-Overflow","Format-String","Arbitrary-Write","Info-Leak"}

def looks_exploitable(va: Dict[str, Any]) -> bool:
    """Heuristic: decide if a vulnerability assessment is a good exploit candidate."""
    if not va or not va.get("is_vulnerability"):
        return False
    # classification field
    cls = (va.get("classification") or "").strip()
    if cls in CLASSES_EXPLOITABLE:
        return True
    # cwe_ids
    cwes = set(va.get("cwe_ids") or [])
    if cwes & HIGH_RISK_CWE:
        return True
    # severity
    sev = (va.get("severity") or "").lower()
    if sev in {"high","critical"}:
        return True
    # textual reasons
    reasons = " ".join(va.get("reasons") or []).lower()
    if any(k in reasons for k in KEYWORDS_EXPLOITABLE):
        return True
    return False

# -------------------- Planner / Implementer orchestration --------------------

async def plan_exploit(apk: Path, cs_json: Dict[str, Any], candidate: Dict[str, Any], model_name: Optional[str], timeout: int, verbose: bool) -> ExploitPlan:
    """Build MCP toolsets and ask Planner to draft an Exploit Plan."""
    # Tokens for relevant .so selection
    tokens = list(set((candidate.get("native_functions") or []) + (candidate.get("jni_methods") or [])))
    # Extract relevant native libs
    with tempfile.TemporaryDirectory(prefix="eval_so_") as td:
        workdir = Path(td)
        so_paths = extract_so_files(apk, workdir)
        relevant = find_relevant_libs(so_paths, tokens) or so_paths[:3]

        # Build MCP servers
        ghidra_server = make_ghidra_server([str(p) for p in relevant], timeout=timeout)
        jadx_server = make_jadx_server(timeout=timeout)

        # Compose Planner agent
        agent = get_agent(PLANNER_SYSTEM_PROMPT, ExploitPlan, [jadx_server, ghidra_server], model_name=model_name)
        user_ctx = {
            "apk_path": str(apk.resolve()),
            "candidate": candidate,
            "call_sequences": cs_json,  # may be None-like structure if absent
            "note": "Crash/logs come from fuzzing; treat as noisy. Produce a minimal, deterministic plan."
        }
        if verbose:
            print_message(BLUE, "PLANNER_CTX", json.dumps(user_ctx)[:8000])
        async with agent:
            res = await agent.run(json.dumps(user_ctx))
            return res.output

def run_script(code: str, device: Optional[str], timeout: int, workdir: Path) -> Dict[str, Any]:
    """Write code to poc.py, run it, capture stdout/stderr/returncode."""
    script_path = workdir / "poc.py"
    script_path.write_text(code)
    cmd = ["python3", str(script_path), "--timeout", str(timeout)]
    if device:
        cmd += ["--device", device]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+30)
    out = proc.stdout or ""
    err = proc.stderr or ""
    return {
        "script_path": str(script_path),
        "returncode": proc.returncode,
        "stdout": out,
        "stderr": err,
        "success": ("EXPLOIT_SUCCESS" in out)
    }

async def implement_and_run(plan: ExploitPlan, model_name: Optional[str], device: Optional[str], max_iters: int, timeout: int, verbose: bool) -> Dict[str, Any]:
    """Implementer loop: generate code, run, fix based on logs, up to max_iters."""
    agent = get_agent(IMPLEMENTER_SYSTEM_PROMPT, str, [], model_name=model_name)
    artifacts: Dict[str, Any] = {"iterations": []}
    with tempfile.TemporaryDirectory(prefix="poc_") as td:
        tmp = Path(td)
        async with agent:
            # First generation
            code = (await agent.run(plan.model_dump_json())).output
            exec_res = run_script(code, device=device, timeout=timeout, workdir=tmp)
            artifacts["iterations"].append({
                "attempt": 1,
                "script_path": exec_res["script_path"],
                "returncode": exec_res["returncode"],
                "stdout_tail": exec_res["stdout"][-4000:],
                "stderr_tail": exec_res["stderr"][-4000:],
                "success": exec_res["success"]
            })
            if exec_res["success"]:
                artifacts["final"] = exec_res
                return artifacts

            # Repair loop
            for i in range(2, max_iters+1):
                feedback = f"""The previous run failed.
Here are the last logs (stdout and stderr). Improve the code. Return the FULL updated Python script only.
STDOUT_START
{exec_res["stdout"][-8000:]}
STDOUT_END
STDERR_START
{exec_res["stderr"][-8000:]}
STDERR_END"""
                code = (await agent.run(feedback)).output
                exec_res = run_script(code, device=device, timeout=timeout, workdir=tmp)
                artifacts["iterations"].append({
                    "attempt": i,
                    "script_path": exec_res["script_path"],
                    "returncode": exec_res["returncode"],
                    "stdout_tail": exec_res["stdout"][-4000:],
                    "stderr_tail": exec_res["stderr"][-4000:],
                    "success": exec_res["success"]
                })
                if exec_res["success"]:
                    artifacts["final"] = exec_res
                    return artifacts
    # If we get here, no success
    artifacts["final"] = artifacts["iterations"][-1] if artifacts["iterations"] else None
    return artifacts

# -------------------- CLI --------------------

def parse_args():
    p = argparse.ArgumentParser(description="Separated evaluation: exploitability filter + exploit generation/repair loop.")
    p.add_argument("apk", type=Path, help="Path to the APK file")
    p.add_argument("cs", type=Path, help="Path to Call Sequence (CS) JSON file")
    p.add_argument("--device", type=str, help="ADB device serial (as shown by `adb devices`)")
    p.add_argument("-a", "--assessments", type=Path, default=Path("assessments.json"), help="Path to vulnerability assessments JSON")
    p.add_argument("-m", "--model-name", type=str, default=None, help="LLM model name (default from env LLM_MODEL_NAME)")
    p.add_argument("--max-iters", type=int, default=3, help="Max implement-fix iterations per candidate")
    p.add_argument("--eval-timeout", type=int, default=120, help="Timeout (seconds) for PoC run")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logs (echo prompts/contexts)")
    p.add_argument("-d", "--debug", action="store_true", help="Debug logs")
    p.add_argument("-o", "--json-out", type=Path, default=Path("evaluation_report.json"), help="Where to write the evaluation JSON report")
    return p.parse_args()

# -------------------- Main --------------------

def main():
    args = parse_args()
    if not is_valid_apk(args.apk):
        print_message(RED, "ERROR", f"Invalid APK: {args.apk}")
        sys.exit(1)
    if not args.cs.is_file():
        print_message(RED, "ERROR", f"CS file not found: {args.cs}")
        sys.exit(1)
    if not args.assessments.is_file():
        print_message(RED, "ERROR", f"Assessments JSON not found: {args.assessments}")
        sys.exit(1)

    # Load inputs
    cs_json = json.loads(args.cs.read_text())
    assessments = json.loads(args.assessments.read_text())
    if isinstance(assessments, dict) and "analysisResults" in assessments:
        # support the format used in some versions
        items = assessments.get("analysisResults", [])
    else:
        items = assessments if isinstance(assessments, list) else []

    # Stage 1: filter exploitable
    candidates = [va for va in items if looks_exploitable(va)]
    print_message(CYAN, "FILTER", f"{len(candidates)}/{len(items)} candidates selected as exploitable")

    # Stage 2: attempt exploitation per candidate
    overall = {
        "apk_path": str(args.apk.resolve()),
        "apk_sha256": sha256_file(args.apk),
        "device": args.device,
        "cs_path": str(args.cs.resolve()),
        "assessments_path": str(args.assessments.resolve()),
        "candidates": candidates,
        "attempts": []
    }

    async def process_all():
        for idx, cand in enumerate(candidates, 1):
            print_message(BLUE, "CANDIDATE", f"[{idx}/{len(candidates)}] {cand.get('package')} :: {cand.get('native_functions')}")
            # Plan
            plan = await plan_exploit(args.apk, cs_json, cand, args.model_name, args.eval_timeout, args.verbose)
            if args.verbose:
                print_message(PURPLE, "PLAN", plan.model_dump_json(indent=2))

            # Implement & run
            artifacts = await implement_and_run(plan, args.model_name, args.device, args.max_iters, args.eval_timeout, args.verbose)
            success = bool(artifacts.get("final", {}).get("success"))
            overall["attempts"].append({
                "candidate_index": idx,
                "candidate": cand,
                "plan": plan.model_dump(),
                "artifacts": artifacts,
                "success": success
            })
            color = GREEN if success else YELLOW
            print_message(color, "RESULT", f"Candidate {idx}: {'SUCCESS' if success else 'FAIL'}")

    asyncio.run(process_all())

    # Save report
    args.json_out.write_text(json.dumps(overall, indent=2))
    print_message(GREEN, "OK", f"Evaluation report saved to: {args.json_out}")

if __name__ == "__main__":
    main()
