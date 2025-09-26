import json
import os
import sys
from typing import List, Optional
from pydantic import BaseModel, Field

from Crashes import Crashes
from MCPs.ghidraMCP import make_ghidra_server
from MCPs.jadxMCP import make_jadx_server
from utils import *
from .get_agent import get_agent
from .prompts.vulnAssesment_prompts import ASSESSMENT_SYSTEM_PROMPT

class EvidenceItem(BaseModel):
    function: Optional[str] = None       # e.g., "mp4_write_one_h264"
    address: Optional[str] = None        # e.g., "0x7fa1234"
    file: Optional[str] = None           # source/path if known
    snippet: Optional[str] = None        # short decompiled excerpt
    note: Optional[str] = None           # brief explanation

class VulnAssessment(BaseModel):
    is_vulnerability: bool = Field(..., description="True if likely a genuine vulnerability")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in [0,1]")
    reasons: List[str] = Field(default_factory=list, description="Bullet points supporting the decision")

    # Existing fields you already had:
    jni_methods: List[str] = Field(default_factory=list)
    native_functions: List[str] = Field(default_factory=list)

    # New, helpful fields (all optional):
    classification: Optional[str] = Field(default=None, description="e.g., 'OOB-Write', 'UAF', 'Null-Deref', 'Env/Harness'")
    cwe_ids: List[str] = Field(default_factory=list, description="Relevant CWE identifiers, e.g., ['CWE-787']")
    severity: Optional[str] = Field(default=None, description="One of: low/medium/high/critical")

    # Echo/normalization of the specific crash being judged (helps when you iterate over crashes):
    app_native_function: Optional[str] = None
    jni_bridge_method: Optional[str] = None
    stack_trace: List[str] = Field(default_factory=list)

    affected_libraries: List[str] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)

    # Optional suggestions + context
    recommendations: List[str] = Field(default_factory=list)
    assumptions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

    
# TODO
# def mcp_vuln_ass_needed_files(..)

async def mcp_vuln_assessment(model_name: str, files: List[str], crashes : Crashes, relevant: List[Path], timeout: int = 45, verbose: bool = False) -> List[VulnAssessment]:
    """
    Run the assessment agent once, then feed it each CrashEntry (one by one).
    Returns a list of VulnAssessment, in the same order as 'crashes'.
    """
    # Start MCP servers once
    ghidra_server = make_ghidra_server([str(p) for p in relevant], timeout=timeout)
    jadx_server = make_jadx_server(timeout=timeout)

    results: List[VulnAssessment] = []

    if verbose:
        print_message(BLUE, "PROMPT", ASSESSMENT_SYSTEM_PROMPT)

    # Build agent with BOTH toolsets
    async with get_agent(
        ASSESSMENT_SYSTEM_PROMPT,
        VulnAssessment,
        [jadx_server, ghidra_server],
        model_name=model_name
    ) as agent:

        for crash in crashes:
            payload = str(crash)

            if verbose:
                print_message(CYAN, "REQUEST", payload)

            resp = await agent.run(payload)
            vuln: VulnAssessment = resp.output
            results.append(vuln)

            if verbose:
                print_message(PURPLE, "RESPONSE", vuln)

    return results
        