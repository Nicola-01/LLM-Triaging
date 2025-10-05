from dataclasses import asdict, dataclass, is_dataclass
import json
import textwrap
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field

from CrashSummary import CrashSummary, Crashes
from MCPs.ghidraMCP import make_ghidra_server
from MCPs.jadxMCP import make_jadx_server
from utils import *
from .get_agent import get_agent
from .prompts.vulnAssesment_prompts import ASSESSMENT_SYSTEM_PROMPT

@dataclass
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

@dataclass
class VulnAssessment(BaseModel):
    """
    Result of a vulnerability assessment for a single crash."""
    is_vulnerability: bool = Field(..., description="True if likely a genuine vulnerability")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in [0,1]")
    reasons: List[str] = Field(default_factory=list, description="Bullet points supporting the decision")
    cwe_ids: List[str] = Field(default_factory=list, description="Relevant CWE identifiers, e.g., ['CWE-787']")
    severity: Optional[str] = Field(default=None, description="One of: low/medium/high/critical")

    affected_libraries: List[str] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)

    recommendations: List[str] = Field(default_factory=list)
    assumptions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    
    def __str__(self) -> str:
        """
        Pretty text rendering of the assessment, including stack, reasons, and evidence.
        Uses compact '(none)' markers when lists are empty.
        """
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

        return (
            "VulnAssessment:\n"
            f"  Verdict           : {verdict}\n"
            f"  Confidence        : {self.confidence:.2f}\n"
            f"  Severity          : {self.severity or '(unknown)'}\n"
            f"  Affected Libraries: {libs_str}\n"
            f"  Reasons           : {reasons_str}\n"
            f"  Evidence          : {evidence_block}\n"
            f"  Recommendations   : {rec_block}\n"
            f"  Assumptions       : {asm_block}\n"
            f"  Limitations       : {lim_block}"
        )

class AnalysisResult(BaseModel):
    """
    Combines a CrashSummary with its corresponding VulnAssessment."""
    crash: CrashSummary
    assessment: VulnAssessment
    
    # model_config = ConfigDict(arbitrary_types_allowed=True, ser_json_inf_nan=False)

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
    analysisResults: List[AnalysisResult]
    
    def __init__(self, **data):
        if "analysisResults" not in data:
            data["analysisResults"] = []
        super().__init__(**data)
        
    def append(self, item: AnalysisResult):
        self.analysisResults.append(item)
        
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
    

async def mcp_vuln_assessment(model_name: str, crashes : Crashes, relevant: List[Path], timeout: int = 45, verbose: bool = False, debug: bool = False) -> AnalysisResults:
    """
    Run the assessment agent once, then feed it each CrashEntry (one by one).
    Returns a list of VulnAssessment, in the same order as 'crashes'.
    """
    # Start MCP servers once
    ghidra_server = make_ghidra_server([str(p) for p in relevant], timeout=timeout)
    jadx_server = make_jadx_server(timeout=timeout)

    results = AnalysisResults()

    if verbose:
        print_message(BLUE, "SYSTEM_PROMPT", ASSESSMENT_SYSTEM_PROMPT)

    # Build agent with BOTH toolsets
    async with get_agent(
        ASSESSMENT_SYSTEM_PROMPT,
        VulnAssessment,
        [jadx_server, ghidra_server],
        model_name=model_name
    ) as agent:

        for i, crash in enumerate(crashes, start=1):
            payload = str(crash)
            
            print_message(BLUE, "INFO", f"Assessing crash #{i}")

            if verbose:
                print_message(CYAN, "REQUEST", payload)

            resp = await agent.run(payload)
            vuln: VulnAssessment = resp.output
            results.append(AnalysisResult(crash=crash, assessment=vuln))

            if verbose:
                print_message(PURPLE, "RESPONSE", vuln)
                
            if debug:
                print_message(GREEN, "LLM-USAGE", resp.usage())

    return results
        