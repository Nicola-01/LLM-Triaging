from pathlib import Path
from typing import List, Sequence
from MCPs.CrashSummary import CrashSummary
from flowdroid_gen.callgraph_paths import generateCallGraph, getFlowGraph
from main import find_backtrace_apk_pairs, load_filter_set
from utils import print_message

GRAY='\033[0;30m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'

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
        results: List[CrashSummary] = []
        
        haveCallGraph = generateCallGraph(apk, callGraphDir="/media/nicola/1C805A69805A4982/Games/Server_callGraph")
        print_message(BLUE,"-------------------------")
        if haveCallGraph:
            print_message(GREEN, "HAVE CALLGRAPH", apk)
        else:
            print_message(RED, "DON'T HAVE CALLGRAPH", apk)

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
            JNIBridgeMethod = method
            FuzzHarnessEntry = ""
            ProgramEntry = ""
            StackTrace: List[str] = []
            StackTrace.append(method)

            # Map last 4 lines (if present) to the labeled fields
            n = len(cur)
            for i, line in enumerate(cur):
                if i == 0:
                    # First line already captured as ProcessTermination
                    continue
                elif i == n - 2:
                    FuzzHarnessEntry = line
                elif i == n - 1:
                    ProgramEntry = line
                else:
                    StackTrace.append(line)
            
            callGraph = None
            if haveCallGraph:
                callGraph = getFlowGraph(apk, JNIBridgeMethod, callGraphDir="/media/nicola/1C805A69805A4982/Games/Server_callGraph", max_depth=1, debug=debug)
                if len(callGraph) > 0:
                    print_message(GREEN, "REACHABLE", JNIBridgeMethod)
                else:
                    print_message(RED, "NOT REACHABLE", JNIBridgeMethod)
                
            
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

apk_list = Path("Other/allAPKs.txt")
target_APK = Path("APKs")

apk_filter = load_filter_set(apk_list, debug=False)
pairs = find_backtrace_apk_pairs(target_APK, apk_filter=apk_filter, debug=False)

oldAPK = ""
for pair in pairs:
    backtraces, apk = pair
    
    if(oldAPK != apk):
        print_message(BLUE, apk)
        haveCallGraph = generateCallGraph(apk, callGraphDir="/media/nicola/1C805A69805A4982/Games/Server_callGraph")
        if not haveCallGraph:
            print_message(RED, "DON'T HAVE CALLGRAPH", apk)
            oldAPK = apk
            continue
    oldAPK = apk
    
    

    method = backtraces.parent.parent.name.split("@")[0]
    text = backtraces.read_text(errors="replace")
    crashForBacktrace = text.count("###################################################")
    status = getFlowGraph(apk, method, max_depth = 1, callGraphDir="/media/nicola/1C805A69805A4982/Games/Server_callGraph")
    
    if status:
        print_message(GREEN, method, f"{crashForBacktrace} reachable")
    else: 
        print_message(RED, method, f"{crashForBacktrace} unreachable")