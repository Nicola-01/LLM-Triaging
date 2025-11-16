"""
Module overview:
- Purpose: Provide high-level description of this module.
- Important classes/functions are documented inline.
"""

import textwrap
from typing import List, Iterable, Union, Sequence
from dataclasses import dataclass
from pathlib import Path

from flowdroid_gen.callgraph_paths import getFlowGraph
from utils import print_message, YELLOW

# ----------------------------
# Data model
# ----------------------------

@dataclass
class CrashSummary:
    """
    Represents a single crash entry parsed from the report.

    Fields:
        ProcessTermination: The first line in the section, describing how the process died.
        StackTrace:         Middle lines (except the last 3), preserved order.
        JNIBridgeMethod:    The line at position (len(section) - 3).
        FuzzHarnessEntry:   The line at position (len(section) - 2).
        ProgramEntry:       The last line in the section (typically 'main').
    """
    # ProcessTermination (str): Process termination.
    # Fields
    # - **ProcessTermination** (str): Process termination.
    # - **StackTrace** (List[str]): Stack trace.
    # - **JNIBridgeMethod** (str): J n i bridge method.
    # - **FuzzHarnessEntry** (str): Fuzz harness entry.
    # - **ProgramEntry** (str): Program entry.
    ProcessTermination: str
    StackTrace: List[str]
    JavaCallGraph: List[str]
    JNIBridgeMethod: str
    FuzzHarnessEntry: str
    ProgramEntry: str
    
    def __str__(self) -> str:
        """
        Pretty text rendering. When the stack is empty prints '(empty)';
        otherwise prints indented lines, one per frame.
        """
        stack_str = (
            "(empty)"
            if not self.StackTrace
            else "\n" + textwrap.indent("\n".join(self.StackTrace), "        ")
        )
        javaCallGraph_str = (
            "(empty)"
            if not self.JavaCallGraph
            else "\n" + textwrap.indent("\n".join(self.StackTrace), "        ")
        )
        
        
        return (
            "CrashEntry:\n"
            f"  Process Termination : {self.ProcessTermination}\n"
            f"  JNI Bridge Method   : {self.JNIBridgeMethod}\n"
            f"  Native Stack Trace  : {stack_str}\n"
            f"  Java Call Graph     : {javaCallGraph_str}\n"
            f"  Fuzz Harness Entry  : {self.FuzzHarnessEntry}\n"
            f"  Program Entry       : {self.ProgramEntry}"
        )


# ----------------------------
# Parser and container
# ----------------------------

class Crashes:
    """
    Container + parser for a crash report file.

    Usage:
        crashes = Crashes(Path("report.txt"))
        print(crashes)        # summary of all entries
        first = crashes[0]    # CrashEntry
        top3  = crashes[:3]   # List[CrashEntry]
        for c in crashes:
            print(c.ProgramEntry)

    Notes:
        - This parser assumes each crash section is delimited by lines of hashes:
            ################ CRASH NR X ######################
            <frames...>
            ###################################################
        - Within each section, the first line is treated as 'ProcessTermination',
          the last three lines map to (JNIBridgeMethod, FuzzHarnessEntry, ProgramEntry), 
          and the remaining middle lines form the stack.
        - If a section has < 5 lines, the role mapping will still proceed; missing
          fields will remain empty strings.
    """

    def __init__(self, apk: Path, crash_report_path: Path, debug = False):
        """
        Parse the given crash report file immediately and store results internally.
        """
        self.__entries: List[CrashSummary] = self.__parse_crash_report(apk, crash_report_path, debug)

    # ---- Read-only access to entries ----
    @property
    def entries(self) -> Sequence[CrashSummary]:
        """Read-only view of parsed entries."""
        return tuple(self.__entries)

    # ---- Core parsing ----
    def __parse_crash_report(self, apk: Path, path: Path, debug) -> List[CrashSummary]:
        """
        Parse the crash report format produced by your tool.

        Expected layout for each crash section:
            ################ CRASH NR X ######################
            <frames...>
            ###################################################

        Returns:
            A list of CrashEntry objects, in the order they appear.
        """
        text = path.read_text(errors="replace")
        # Drop empty lines, keep order; strip trailing/leading spaces
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        cur: List[str] = []
        results: List[CrashSummary] = []

        def flush() -> None:
            """
            Convert the accumulated lines for the current section ('cur')
            into a CrashEntry and append it to 'results'. Resets 'cur'.
            """
            nonlocal cur
            if not cur:
                return

            # Initialize defaults to keep behavior predictable even with short sections
            ProcessTermination = cur[0] if len(cur) >= 1 else ""
            JNIBridgeMethod = ""
            FuzzHarnessEntry = ""
            ProgramEntry = ""
            StackTrace: List[str] = []

            # Map last 4 lines (if present) to the labeled fields
            n = len(cur)
            for i, line in enumerate(cur):
                if i == 0:
                    # First line already captured as ProcessTermination
                    continue
                elif i == n - 3:
                    JNIBridgeMethod = line
                    StackTrace.append(line)
                elif i == n - 2:
                    FuzzHarnessEntry = line
                elif i == n - 1:
                    ProgramEntry = line
                else:
                    StackTrace.append(line)
                    
            depth = 1
            callGraph = None
            while True:
                new_callGraph = getFlowGraph(apk, JNIBridgeMethod, depth, debug=True)
                if not new_callGraph:
                    if debug:
                        print_message(YELLOW, "DEBUG", "Call Graph is null")
                    break
                if len(new_callGraph) < 20:
                    callGraph = new_callGraph
                else:
                    break
                depth += 1
            
            results.append(
                CrashSummary(
                    ProcessTermination=ProcessTermination,
                    StackTrace=StackTrace,
                    JNIBridgeMethod=JNIBridgeMethod,
                    JavaCallGraph=callGraph,
                    FuzzHarnessEntry=FuzzHarnessEntry,
                    ProgramEntry=ProgramEntry,
                )
            )
            cur = []

        in_section = False
        for line in lines:
            if line.startswith("#"):
                flush()            # close any previously open section
                in_section = "CRASH NR" in line
                continue

            # Inside a section, collect frames
            if in_section:
                cur.append(line)

        # Flush the last open section, if any
        flush()
        return results

    # ---- Sequence protocol / helpers ----
    def __len__(self) -> int:
        """Number of parsed crash entries."""
        return len(self.__entries)

    def __iter__(self) -> Iterable[CrashSummary]:
        """Iterate over crash entries in order."""
        return iter(self.__entries)

    def __getitem__(self, key: Union[int, slice]) -> Union[CrashSummary, List[CrashSummary]]:
        """Indexing and slicing support (e.g., crashes[0], crashes[:3])."""
        return self.__entries[key]
    
    def get_JNIBridgeMethods(self) -> List[str]:
        """Extract the JNIBridgeMethod from each crash entry."""
        return [entry.JNIBridgeMethod for entry in self.__entries if entry.JNIBridgeMethod]

    def __repr__(self) -> str:
        """Unambiguous summary for debugging and REPL."""
        return f"Crashes(n_entries={len(self)})"

    def __str__(self) -> str:
        """
        Human-friendly summary: one line per crash, with compact fields.
        Note: for full pretty-printing of an entry, print the CrashEntry itself.
        """
        lines = [f"Crashes: {len(self)} entries"]
        for i, e in enumerate(self.__entries):
            lines.append(
                f"- Crash #{i}: [process_termination='{e.ProcessTermination}', "
                f"stack_len={len(e.StackTrace)}, "
                f"jni_bridge_method='{e.JNIBridgeMethod}', "
                f"fuzz_harness_entry='{e.FuzzHarnessEntry}', "
                f"program_entry='{e.ProgramEntry}']"
            )
        return "\n".join(lines)