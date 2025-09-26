import textwrap
from typing import List, Iterable, Union, Sequence
from dataclasses import dataclass
from pathlib import Path

# ----------------------------
# Data model
# ----------------------------

@dataclass
class CrashEntry:
    """
    Represents a single crash entry parsed from the report.

    Fields:
        ProcessTermination: The first line in the section, describing how the process died.
        StackTrace:         Middle lines (except the last 4), preserved order.
        AppNativeFunction:  The line at position (len(section) - 4).
        JNIBridgeMethod:    The line at position (len(section) - 3).
        FuzzHarnessEntry:   The line at position (len(section) - 2).
        ProgramEntry:       The last line in the section (typically 'main').
    """
    ProcessTermination: str
    StackTrace: List[str]
    AppNativeFunction: str
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
        return (
            "CrashEntry:\n"
            f"  Process Termination : {self.ProcessTermination}\n"
            f"  Stack Trace         : {stack_str}\n"
            f"  App Native Function : {self.AppNativeFunction}\n"
            f"  JNI Bridge Method   : {self.JNIBridgeMethod}\n"
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
          the last four lines map to (AppNativeFunction, JNIBridgeMethod,
          FuzzHarnessEntry, ProgramEntry), and the remaining middle lines form the stack.
        - If a section has < 5 lines, the role mapping will still proceed; missing
          fields will remain empty strings.
    """

    # Class-level constants to recognize section boundaries
    _SECTION_START_TOKEN = "CRASH NR"

    def __init__(self, crash_report_path: Path):
        """
        Parse the given crash report file immediately and store results internally.
        """
        self.__entries: List[CrashEntry] = self.__parse_crash_report(crash_report_path)

    # ---- Read-only access to entries ----
    @property
    def entries(self) -> Sequence[CrashEntry]:
        """Read-only view of parsed entries."""
        return tuple(self.__entries)

    # ---- Core parsing ----
    def __parse_crash_report(self, path: Path) -> List[CrashEntry]:
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
        results: List[CrashEntry] = []

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
            AppNativeFunction = ""
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
                elif i == n - 4:
                    AppNativeFunction = line
                elif i == n - 3:
                    JNIBridgeMethod = line
                elif i == n - 2:
                    FuzzHarnessEntry = line
                elif i == n - 1:
                    ProgramEntry = line
                else:
                    StackTrace.append(line)

            results.append(
                CrashEntry(
                    ProcessTermination=ProcessTermination,
                    StackTrace=StackTrace,
                    AppNativeFunction=AppNativeFunction,
                    JNIBridgeMethod=JNIBridgeMethod,
                    FuzzHarnessEntry=FuzzHarnessEntry,
                    ProgramEntry=ProgramEntry,
                )
            )
            cur = []

        in_section = False
        for line in lines:
            # Start of section: a hashes-line containing "CRASH NR"
            if line.startswith("#") and self._SECTION_START_TOKEN in line:
                flush()            # close any previously open section
                in_section = True
                continue

            # End of section: a hashes-line without "CRASH NR"
            if line.startswith("#") and self._SECTION_START_TOKEN not in line:
                flush()
                in_section = False
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

    def __iter__(self) -> Iterable[CrashEntry]:
        """Iterate over crash entries in order."""
        return iter(self.__entries)

    def __getitem__(self, key: Union[int, slice]) -> Union[CrashEntry, List[CrashEntry]]:
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
                f"app_native_function='{e.AppNativeFunction}', "
                f"jni_bridge_method='{e.JNIBridgeMethod}', "
                f"fuzz_harness_entry='{e.FuzzHarnessEntry}', "
                f"program_entry='{e.ProgramEntry}']"
            )
        return "\n".join(lines)
