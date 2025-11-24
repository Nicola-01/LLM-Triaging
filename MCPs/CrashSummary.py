"""
Module overview:
- Purpose: Parse and represent crash reports from the fuzzing pipeline.
- Important classes: CrashSummary, Crashes.
"""

import shutil
import subprocess
import textwrap
from typing import Dict, List, Iterable, Union, Sequence
from dataclasses import dataclass
from pathlib import Path
import re

from flowdroid_gen.callgraph_paths import generateCallGraph, getFlowGraph
from utils import CYAN, RED, print_message, YELLOW

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
        JNIBridgeMethod:    Call from Java to native method.
        FuzzHarnessEntry:   The line at position (len(section) - 2).
        ProgramEntry:       The last line in the section (typically 'main').
    """
    ProcessTermination: str
    StackTrace: List[str]
    JNIBridgeMethod: str
    JavaCallGraph: List[str]
    FuzzHarnessEntry: str
    ProgramEntry: str
    LibMap: Dict[str, List[str]]
    
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
            else "\n" + textwrap.indent("\n".join(self.JavaCallGraph), "        ")
        )
        
        libs_map = [f"{re.sub(r'APKs/[^/]+/lib/[^/]+/', '', str(lib))}: {self.LibMap[lib]}" 
            for lib in sorted(self.LibMap.keys())]
        LibMap_str = (
            "(empty)"
            if not self.LibMap
            else "\n" + textwrap.indent("\n".join(libs_map), "        ")
        )
        
        return (
            "CrashEntry:\n"
            f"  Process Termination : {self.ProcessTermination}\n"
            f"  JNI Bridge Method   : {self.JNIBridgeMethod}\n"
            f"  Native Stack Trace  : {stack_str}\n"
            f"  Java Call Graph     : {javaCallGraph_str}\n"
            f"  Fuzz Harness Entry  : {self.FuzzHarnessEntry}\n"
            f"  Program Entry       : {self.ProgramEntry}\n"
            f"  Library Map         : {LibMap_str}"
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
        method = path.parent.parent.name.split("@")[0]
        # Drop empty lines, keep order; strip trailing/leading spaces
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        cur: List[str] = []
        lib_methods_map: Dict[str, List[str]] = get_libs_method_map(apk=apk,)
        results: List[CrashSummary] = []
        
        haveCallGraph = generateCallGraph(apk)

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
            JNIBridgeMethod = None
            FuzzHarnessEntry = ""
            ProgramEntry = ""
            StackTrace: List[str] = []

            # Map last 4 lines (if present) to the labeled fields
            n = len(cur)
            for i, line in enumerate(cur):
                if i == n - 2:
                    FuzzHarnessEntry = line
                elif i == n - 1:
                    ProgramEntry = line
                StackTrace.append(line)
            
            callGraph = None
            if haveCallGraph:
                callGraph = getFlowGraph(apk, method, debug=debug)
                if len(callGraph) > 0:
                    JNIBridgeMethod = callGraph[0].split(" -> ")[-1].strip()
            
            results.append(
                CrashSummary(
                    ProcessTermination=ProcessTermination,
                    StackTrace=StackTrace,
                    JNIBridgeMethod=JNIBridgeMethod,
                    JavaCallGraph=callGraph,
                    FuzzHarnessEntry=FuzzHarnessEntry,
                    ProgramEntry=ProgramEntry,
                    LibMap=find_relevant_libs(lib_methods_map, StackTrace, method)
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
  
    
def extract_so_files(apk: Path) -> List[Path]:
    """Return all .so files inside apk/lib/ and its subdirectories."""
    lib_dir = apk.parent / "lib"
    if not lib_dir.exists():
        return []
    return sorted(
        [p for p in lib_dir.rglob("*.so") if p.is_file()],
        key=lambda x: str(x)
    )
           
def get_libs_method_map(apk: Path, debug: bool = False) -> Dict[str, List[str]]:
    """
    Given a list of .so files, return those that implement JNI methods,
    preferring specific ABIs in the following order:
        arm64-v8a > armeabi-v7a > armeabi > arm* > x86_64 > x86 > any other.
    """
    so_paths = extract_so_files(apk)

    nm = shutil.which("nm") or shutil.which("llvm-nm")
    if not nm:
        print_message(RED, "ERROR", "Neither 'nm' nor 'llvm-nm' command is available in PATH.")
        print_message(YELLOW, "WARN", "Returning all .so files without filtering.")
        return so_paths

    # Group libs by ABI (directory name under /lib/)
    abi_groups: Dict[str, List[Path]] = {}
    for so in so_paths:
        abi = so.parent.name
        abi_groups.setdefault(abi, []).append(so)

    # Define ABI preference order
    abi_preference = [
        "arm64-v8a",
        "armeabi-v7a",
        "armeabi",
        "arm",
        "x86_64",
        "x86"
    ]

    # Select the best available ABI group
    selected_abi = None
    for abi in abi_preference:
        if abi in abi_groups:
            selected_abi = abi
            break
    if not selected_abi:
        # fallback: pick any remaining ABI folder
        selected_abi = next(iter(abi_groups.keys()), None)

    if debug:
        print_message(CYAN, "DEBUG", f"Selected ABI: {selected_abi}")

    selected_libs = abi_groups.get(selected_abi, [])
    
    libs_map: Dict[Path, List[str]] = {}
    
    # Filter selected libs by JNI symbol presence
    for so in selected_libs:
        try:
            nm_out = subprocess.check_output([nm, "-D", str(so)], text=True, stderr=subprocess.DEVNULL)
            symbols = set(line.split()[-1] for line in nm_out.splitlines() if line and not line.startswith("U "))            
            libs_map[str(so)] = symbols
        except Exception:
            continue
    return libs_map


def find_relevant_libs(lib_methods_map: Dict[Path, List[str]], stackTrace: List[str], method: str):
    relevant_libs_map: Dict[Path, List[str]] = {}
    stackTrace.append(method)
    
    for lib, methods in lib_methods_map.items():
        matched = [m for m in stackTrace if any(m in s for s in methods)]
                    
        for x in ("main", "abort", "memmove"): 
            if x in matched:
                matched.remove(x)
                
        for m in matched:
            if m.startswith("__"):
                matched.remove(m)
                
        if matched:
            relevant_libs_map.setdefault(lib, []).extend(matched)
            
    return relevant_libs_map