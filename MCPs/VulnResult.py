"""
Module overview:
- Purpose: Provide high-level description of this module.
- Important classes/functions are documented inline.
"""

from dataclasses import asdict, dataclass, is_dataclass
import json
import textwrap
from typing import List, Optional
from pydantic import BaseModel, Field

from MCPs.CrashSummary import CrashSummary

from ghidraMCP_helper_functions import *
from utils import *

class EvidenceItem(BaseModel):
    """
    A single piece of evidence supporting a vulnerability assessment.
    """
    # function (Optional[str]): Function.
    # Fields
    # - **function** (Optional[str]): Function.
    # - **address** (Optional[str]): Address.
    # - **file** (Optional[str]): File.
    # - **snippet** (Optional[str]): Snippet.
    # - **note** (Optional[str]): Note.
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

class VulnResult(BaseModel):
    """
    Result of a vulnerability assessment for a single crash.
    """
    # is_vulnerability (bool): Is vulnerability.
    # Fields
    # - **is_vulnerability** (bool): Is vulnerability.
    # - **confidence** (float): Confidence.
    # - **reasons** (List[str]): Reasons.
    # - **cwe_ids** (List[str]): Cwe ids.
    # - **severity** (Optional[str]): Severity.
    # - **affected_libraries** (List[str]): Affected libraries.
    # - **evidence** (List[EvidenceItem]): Evidence.
    # - **recommendations** (List[str]): Recommendations.
    # - **assumptions** (List[str]): Assumptions.
    # - **limitations** (List[str]): Limitations.   
    
    is_vulnerability: bool = Field(..., description="True if the crash likely reflects a real code vulnerability.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in [0-1]; >=0.9 confirmed, <0.3 unlikely.")
    reasons: List[str] = Field(default_factory=list, description="Key bullet points supporting the decision.")
    cwe_ids: List[str] = Field(default_factory=list, description="Relevant CWE IDs, e.g. ['CWE-787'].")
    severity: Optional[str] = Field(default=None, description="Impact level: low, medium, high, or critical.")
    
    affected_libraries: List[str] = Field(default_factory=list, description="Libraries (.so) involved in the crash.")
    evidence: List[EvidenceItem] = Field(default_factory=list, description="Supporting code evidence or snippets.")
    
    recommendations: List[str] = Field(default_factory=list, description="Actionable next steps or fixes.")
    assumptions: List[str] = Field(default_factory=list, description="Assumptions made during reasoning.")
    limitations: List[str] = Field(default_factory=list, description="Missing info or analysis uncertainties.")
    
    
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
            "VulnDetection:\n"
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
    Combines a CrashSummary with its corresponding VulnDetection.
    """
    # crash (CrashSummary): Crash.
    # Fields
    # - **crash** (CrashSummary): Crash.
    # - **assessment** (VulnDetection): Detection.
    crash: CrashSummary
    assessment: VulnResult
    
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
    # analysisResults (List[AnalysisResult]): Analysis results.
    # Fields
    # - **analysisResults** (List[AnalysisResult]): Analysis results.
    """
    Init.
    
    Args:
        **data: Description.
    
    Returns:
        Any: Description.
    """
    analysisResults: List[AnalysisResult] = Field(default_factory=list)
    
    # def __init__(self, **data):
    #     if "analysisResults" not in data:
    #         data["analysisResults"] = []
    
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