"""
Module overview:
- Purpose: Define the data model for vulnerability assessment results.
- Important classes: VulnResult, AnalysisResult, EvidenceItem.
"""

from dataclasses import asdict, dataclass, is_dataclass
import json
import textwrap
from typing import List, Optional
from pydantic import BaseModel, Field

from MCPs.CrashSummary import CrashSummary

from ghidra_helper_functions import *
from utils import *

class EvidenceItem(BaseModel):
    """
    A single piece of evidence supporting a vulnerability assessment.
    """
    function: Optional[str] = None       # e.g., "mp4_write_one_h264"
    address: Optional[str] = None        # e.g., "0x7fa1234"
    file: Optional[str] = None           # source/path if known
    snippet: Optional[str] = None        # short decompiled excerpt
    note: Optional[str] = None           # brief explanation
    
    
    def __str__(self) -> str:
        """Pretty-print a single piece of evidence."""
        # Prepare snippet block (indented, multiline-safe)
        if self.snippet:
            snippet_block = "\n" + textwrap.indent(self.snippet.strip(), "        ")
        else:
            snippet_block = " (none)"

        return (
            "EvidenceItem:\n"
            f"  Function : {self.function or '(unknown)'}\n"
            f"  Address  : {self.address or '(unknown)'}\n"
            f"  File     : {self.file or '(unknown)'}\n"
            f"  Note     : {self.note or '(none)'}\n"
            f"  Snippet  :{snippet_block}"
        )
        
class Exploit(BaseModel):
    """
    Proof-of-concept exploit information for reproducing or triggering the vulnerability.
    """

    exploitability: str = Field(default="unknown", description="Exploitability level: none, theoretical, practical.")
    trigger_method: Optional[str] = Field(default=None, description="Mechanism that triggers the vulnerability, e.g. malformed intent.")
    prerequisites: List[str] = Field(default_factory=list, description="Environmental or permission prerequisites for the exploit.")
    exploit_pipeline: List[str] = Field(default_factory=list, description= "Ordered steps that describe the exploitation flow from initial setup to triggering the vulnerability.")
    poc_commands: List[str] = Field(default_factory=list, description="Fully copy/paste-ready ADB or shell commands to reproduce the crash or exploit.")
    poc_files: List[str] = Field(default_factory=list, description="Paths to crafted payload files used for exploitation.")
    notes: Optional[str] = Field(default=None, description="Additional technical notes.")
    
    def __str__(self) -> str:
        """
        Pretty-print the exploit information in a structured, readable format.
        """
        prereq_block = (
            " (none)"
            if not self.prerequisites
            else "\n" + textwrap.indent("\n".join(f"- {p}" for p in self.prerequisites), "        ")
        )
        pipe_block = (
            " (none)"
            if not self.exploit_pipeline
            else "\n" + textwrap.indent("\n".join(f"{i+1}. {s}" for i, s in enumerate(self.exploit_pipeline)), "        ")
        )
        cmd_block = (
            " (none)"
            if not self.poc_commands
            else "\n" + textwrap.indent("\n".join(f"$ {c}" for c in self.poc_commands), "        ")
        )
        file_block = (
            " (none)"
            if not self.poc_files
            else "\n" + textwrap.indent("\n".join(f"- {f}" for f in self.poc_files), "        ")
        )

        notes_block = f" {self.notes}" if self.notes else " (none)"

        return (
            f"  Exploitability : {self.exploitability}\n"
            f"  Trigger Method : {self.trigger_method or '(none)'}\n"
            f"  Prerequisites  : {prereq_block}\n"
            f"  Pipeline       : {pipe_block}\n"
            f"  PoC Commands   : {cmd_block}\n"
            f"  PoC Files      : {file_block}\n"
            f"  Notes          : {notes_block}"
        )

class VulnResult(BaseModel):
    """
    Result of a vulnerability assessment for a single crash.
    """
    
    chain_of_thought: List[str] = Field(..., description="A detailed, step-by-step internal monologue BEFORE classifying")
    is_vulnerability: bool = Field(..., description="True if the crash likely reflects a real code vulnerability.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in [0-1]; >=0.9 confirmed, <0.3 unlikely.")
    reasons: List[str] = Field(default_factory=list, description="Key bullet points supporting the decision.")
    cwe_ids: List[str] = Field(default_factory=list, description="Relevant CWE IDs, e.g. ['CWE-787'].")
    severity: Optional[str] = Field(default=None, description="Impact level: low, medium, high, or critical.")
    
    affected_libraries: List[str] = Field(default_factory=list, description="Libraries (.so) involved in the crash.")
    evidence: List[EvidenceItem] = Field(default_factory=list, description="Supporting code evidence or snippets.")
    call_sequence : List[str] = Field(default_factory=list, description="Sequence of function calls leading to the vulnerable code region.")
    
    recommendations: List[str] = Field(default_factory=list, description="Actionable next steps or fixes.")
    assumptions: List[str] = Field(default_factory=list, description="Assumptions made during reasoning.")
    limitations: List[str] = Field(default_factory=list, description="Missing info or analysis uncertainties.")
    
    exploit: Optional[Exploit] = Field(default=None, description="Exploitability assessment and PoC commands.")
    
    def __str__(self) -> str:
        """
        Pretty text rendering of the assessment, including stack, reasons, evidence,
        and exploit information. Uses compact '(none)' markers when lists are empty.
        """
        CoT_str = " (none)" if not self.chain_of_thought else "\n" + textwrap.indent("\n".join(f"- {r}" for r in self.chain_of_thought), "        ")
        verdict = "LIKELY VULNERABILITY" if self.is_vulnerability else "LIKELY NOT A VULNERABILITY"
        reasons_str = " (none)" if not self.reasons else "\n" + textwrap.indent("\n".join(f"- {r}" for r in self.reasons), "        ")
        libs_str = ", ".join(self.affected_libraries) if self.affected_libraries else "(none)"

        # Evidence block
        if not self.evidence:
            evidence_block = " (none)"
        else:
            evidence_block = "\n" + textwrap.indent(
                "\n\n".join(str(e) for e in self.evidence),
                "        "
            )

        # Recommendations / assumptions / limitations
        rec_block = " (none)" if not self.recommendations else "\n" + textwrap.indent("\n".join(f"- {r}" for r in self.recommendations), "        ")
        asm_block = " (none)" if not self.assumptions else "\n" + textwrap.indent("\n".join(f"- {a}" for a in self.assumptions), "        ")
        lim_block = " (none)" if not self.limitations else "\n" + textwrap.indent("\n".join(f"- {l}" for l in self.limitations), "        ")
        
        # Call sequence
        call_seq_block = (
            " (none)"
            if not getattr(self, "call_sequence", [])
            else "\n" + textwrap.indent("\n".join(f"- {c}" for c in self.call_sequence), "        ")
        )

        if hasattr(self, "exploit") and self.exploit is not None:
            exploit_block = "\n" + textwrap.indent(str(self.exploit), "        ")
        else:
            exploit_block = " (none)"

        return (
            "VulnDetection:\n"
            f"  Chain of Thought  : {CoT_str}\n"
            f"  Verdict           : {verdict}\n"
            f"  Confidence        : {self.confidence:.2f}\n"
            f"  Severity          : {self.severity or '(unknown)'}\n"
            f"  Affected Libraries: {libs_str}\n"
            f"  Reasons           : {reasons_str}\n"
            f"  Evidence          : {evidence_block}\n"
            f"  Call Sequence     : {call_seq_block}\n"
            f"  Recommendations   : {rec_block}\n"
            f"  Assumptions       : {asm_block}\n"
            f"  Limitations       : {lim_block}\n"
            f"  Exploit           : {exploit_block}"
        )

class TokenUsage(BaseModel):
    """
    Tracks token usage for LLM interactions.
    """
    input_tokens: int = 0
    output_tokens: int = 0
    
class Statistics(BaseModel):
    """
    Statistics regarding the analysis process, including time and token usage.
    """
    time: str = "00:00:00"
    llm_requests: int = None
    llm_tool_calls: int = None
    input_tokens: int = None
    output_tokens: int = None
    
    def __str__(self) -> str:
        lines = [f"Statistics:", f"  Time           : {self.time}"]
        if self.llm_requests is not None:   lines.append(f"  LLM Requests   : {self.llm_requests}")
        if self.llm_tool_calls is not None: lines.append(f"  LLM Tool Calls : {self.llm_tool_calls}")
        if self.input_tokens is not None:   lines.append(f"  Input Tokens   : {self.input_tokens}")
        if self.output_tokens is not None:  lines.append(f"  Output Tokens  : {self.output_tokens}")
        return "\n".join(lines)

class AnalysisResult(BaseModel):
    """
    Combines a CrashSummary with its corresponding VulnDetection.
    """
    crash: CrashSummary
    assessment: VulnResult
    statistics: Statistics
    
    def to_json(self, *, indent: int = 2, exclude_none: bool = True, ensure_ascii: bool = False) -> str:
        """
        Serialize this AnalysisResult to a JSON string.
        - Converts `crashes` (dataclass) via dataclasses.asdict
        - Drops None fields if `exclude_none=True`
        - Uses pretty indentation by default
        """
        # Dump pydantic side first (this will leave `crashes` as the dataclass object)
        data = self.model_dump(mode="python", exclude_none=exclude_none)

        # Normalize dataclass -> dict for JSON
        if is_dataclass(self.crash):
            data["crash"] = asdict(self.crash)

        return json.dumps(data, indent=indent, ensure_ascii=ensure_ascii)
    
    

class AnalysisResults(BaseModel):
    """
    Collection of AnalysisResult entries.
    """

    analysisResults: List[AnalysisResult] = Field(default_factory=list)
    
    """
    Append.
    
    Args:
        item: Description.
    
    Returns:
        Any: Description.
    """
    def append(self, item: AnalysisResult):
        
        try:
            self.analysisResults.append(item)
        except Exception as e:
            print_message(RED, "ERROR", f"Failed to append AnalysisResult: {e}")
            print_message(RED, "ERROR", f"Item: {item}")
            
            raise e
        
    def to_json(self, *, indent: int = 2, exclude_none: bool = True, ensure_ascii: bool = False) -> str:
        """
        Serialize this AnalysisResults to a JSON string.
        - Converts `crashes` (dataclass) via dataclasses.asdict
        - Drops None fields if `exclude_none=True`
        - Uses pretty indentation by default
        """
        # Dump pydantic side first (this will leave `crashes` as the dataclass object)
        data = self.model_dump(mode="python", exclude_none=exclude_none)

        # Normalize dataclass -> dict for JSON
        for entry in data["analysisResults"]:
            if is_dataclass(entry["crash"]):
                entry["crash"] = asdict(entry["crash"])

        return json.dumps(data, indent=indent, ensure_ascii=ensure_ascii)
    
    def to_json_file(self, path: Path, *, indent: int = 2, exclude_none: bool = True, ensure_ascii: bool = False) -> None:
        """
        Serialize to JSON and write to `path`.
        """
        s = self.to_json(indent=indent, exclude_none=exclude_none, ensure_ascii=ensure_ascii)
        path.write_text(s, encoding="utf-8")