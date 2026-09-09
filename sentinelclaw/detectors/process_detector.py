import logging
import re

logger = logging.getLogger(__name__)


SUSPICIOUS_DIRECTORIES = [
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
]

HIGH_RISK_TOOL_NAMES = {
    "mimikatz.exe",
    "procdump.exe",
}

LOLBINS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "wscript.exe",
    "cscript.exe",
    "bitsadmin.exe",
}

OFFICE_PARENT_PROCESSES = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
}

BROWSER_PARENT_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
}

SCRIPT_OR_SHELL_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
}

POWERSHELL_SUSPICIOUS_ARGUMENTS = [
    "-enc",
    "-encodedcommand",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "iex ",
    "invoke-webrequest",
    "iwr ",
    "new-object net.webclient",
]

CMD_SUSPICIOUS_ARGUMENTS = [
    "powershell",
    "certutil",
    "bitsadmin",
    "mshta",
]

CERTUTIL_SUSPICIOUS_ARGUMENTS = [
    "-urlcache",
    "-decode",
    "-decodehex",
]

RUNDLL32_SUSPICIOUS_ARGUMENTS = [
    "javascript:",
    "http://",
    "https://",
]

REGSVR32_SUSPICIOUS_ARGUMENTS = [
    "/i:http",
    "/i:https",
    "scrobj.dll",
]

MSHTA_SUSPICIOUS_ARGUMENTS = [
    "http://",
    "https://",
    "javascript:",
    "vbscript:",
]

# --- Linux-specific indicators (P1-10) ---

LINUX_SHELLS = {
    "bash",
    "sh",
    "dash",
    "zsh",
    "ksh",
    "ash",
    "csh",
    "tcsh",
}

LINUX_INTERPRETERS = {
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "php",
    "lua",
    "node",
}

LINUX_NET_TOOLS = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
}

LINUX_LOLBINS = LINUX_SHELLS | LINUX_INTERPRETERS | LINUX_NET_TOOLS

LINUX_WRITABLE_DIRECTORIES = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/user/",
)

LINUX_SUSPICIOUS_PARENTS = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
}

LINUX_ENCODED_MARKERS = [
    "base64",
    "frombase64",
    "exec(",
    "eval(",
    "chr(",
    "decode",
    "\\x",
]

_DOWNLOAD_EXEC_PATTERN = re.compile(
    r"(?:curl|wget)\s+"
    r"\S+.*\|\s*"
    r"(?:ba|d|k|z)?sh\b"
)

_NET_SHELL_PATTERN = re.compile(
    r"(?:\s-[ec]\b|"
    r"--exec|--sh-exec|"
    r"/bin/(?:ba|d)?sh\b)"
)


def command_line_text(process: dict) -> str:
    command_line = process.get("command_line") or []

    if isinstance(command_line, str):
        return command_line.lower()

    return " ".join(str(item) for item in command_line).lower()


def add_finding(
    findings: list[dict],
    severity: str,
    rule_id: str,
    title: str,
    description: str,
    process: dict,
    mitre: dict | None = None,
) -> None:
    evidence = {
        "executable": process.get("executable"),
        "command_line": process.get("command_line"),
        "ppid": process.get("ppid"),
        "create_time": process.get("create_time"),
    }

    finding = {
        "severity": severity,
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "pid": process.get("pid"),
        "process_name": process.get("name"),
        "parent_name": process.get("parent_name"),
        "evidence": evidence,
    }

    if mitre:
        finding["mitre"] = mitre

    findings.append(finding)


def is_windows_style_process(process: dict) -> bool:
    """Return whether a process record looks like a Windows process.

    Records are classified by shape (``.exe`` names or backslash paths)
    rather than by the host platform. This keeps the Windows detection
    path byte-identical on Windows hosts while enabling the Linux path
    for POSIX-shaped records regardless of the host running the scan.
    """
    name = (process.get("name") or "").lower()

    if name.endswith(".exe"):
        return True

    executable = process.get("executable") or ""

    if "\\" in executable:
        return True

    if re.match(
        r"^[a-zA-Z]:[\\/]",
        executable,
    ):
        return True

    return False


def analyze_linux_process(
    findings: list[dict],
    process: dict,
    name: str,
    parent_name: str,
    executable: str,
    cmd: str,
) -> None:
    """Emit Linux LOLBin / download-and-execute / encoded findings."""

    if name in LINUX_SHELLS:
        if _DOWNLOAD_EXEC_PATTERN.search(cmd):
            add_finding(
                findings,
                "high",
                "LIN-PROC-001",
                "Shell download-and-execute detected",
                (
                    f"{name} is executing a command that "
                    "downloads content and pipes it into a "
                    "shell interpreter."
                ),
                process,
                mitre={
                    "technique": "T1059.004",
                    "name": "Unix Shell",
                    "tactic": "Execution",
                },
            )

        if parent_name in LINUX_SUSPICIOUS_PARENTS:
            add_finding(
                findings,
                "medium",
                "LIN-PROC-005",
                "Shell spawned by network download tool",
                (
                    f"{parent_name} spawned {name}. This "
                    "parent-child relationship is commonly "
                    "seen during download-and-execute attacks."
                ),
                process,
                mitre={
                    "technique": "T1059.004",
                    "name": "Unix Shell",
                    "tactic": "Execution",
                },
            )

    if name in LINUX_NET_TOOLS:
        if _NET_SHELL_PATTERN.search(cmd):
            add_finding(
                findings,
                "high",
                "LIN-PROC-002",
                "Network tool with shell-execution arguments",
                (f"{name} is running with arguments that can hand a shell to a remote attacker."),
                process,
                mitre={
                    "technique": "T1059.004",
                    "name": "Unix Shell",
                    "tactic": "Execution",
                },
            )

    if name in LINUX_INTERPRETERS:
        has_inline = " -c " in cmd or " -e " in cmd

        obfuscated = any(marker in cmd for marker in LINUX_ENCODED_MARKERS)

        if has_inline and obfuscated:
            add_finding(
                findings,
                "medium",
                "LIN-PROC-003",
                "Interpreter running encoded or obfuscated command",
                (
                    f"{name} was launched with an inline "
                    "command containing encoded or "
                    "obfuscated content."
                ),
                process,
                mitre={
                    "technique": "T1027",
                    "name": "Obfuscated Files or Information",
                    "tactic": "Defense Evasion",
                },
            )

    if name in LINUX_LOLBINS:
        if executable.startswith(LINUX_WRITABLE_DIRECTORIES):
            add_finding(
                findings,
                "medium",
                "LIN-PROC-004",
                "Linux LOLBin executing from user-writable path",
                (
                    f"{name} is a commonly abused utility "
                    "but is executing from a user-writable "
                    "location."
                ),
                process,
                mitre={
                    "technique": "T1204",
                    "name": "User Execution",
                    "tactic": "Execution",
                },
            )


def analyze_processes(
    processes: list[dict],
) -> list[dict]:

    findings: list[dict] = []

    for process in processes:
        name = (process.get("name") or "").lower()

        parent_name = (process.get("parent_name") or "").lower()

        executable = (process.get("executable") or "").lower()

        cmd = command_line_text(process)

        # A missing executable path is only notable for processes that
        # are actual programs (they have a command line). Linux kernel
        # threads (kworker, ksoftirqd, migration, cpuhp, ...) never have
        # an executable and never have argv — flagging each one drowns
        # the findings in noise. An access-denied exe (root-owned daemon
        # inspected unprivileged) is a permission boundary, not a signal.
        # Deleted binaries are covered separately by DEL-001 / the
        # exe_deleted flag.
        if not executable and cmd and not process.get("exe_error"):
            findings.append(
                {
                    "severity": "info",
                    "rule_id": "PROC-003",
                    "title": "Executable path unavailable",
                    "description": (
                        f"The executable path for "
                        f"{name or 'unknown process'} "
                        "could not be determined."
                    ),
                    "pid": process.get("pid"),
                    "evidence": None,
                }
            )

        if is_windows_style_process(process):
            if name in HIGH_RISK_TOOL_NAMES:
                add_finding(
                    findings,
                    "high",
                    "PROC-001",
                    "High-risk security tool detected",
                    (f"{name} matches a monitored credential or process-dumping tool."),
                    process,
                )

            if executable and any(directory in executable for directory in SUSPICIOUS_DIRECTORIES):
                add_finding(
                    findings,
                    "low",
                    "PROC-002",
                    "Process running from user-writable directory",
                    (
                        f"{name or 'Unknown process'} is executing "
                        "from a commonly user-writable location."
                    ),
                    process,
                )

            if name in {
                "powershell.exe",
                "pwsh.exe",
            }:
                matched_arguments = [
                    argument for argument in POWERSHELL_SUSPICIOUS_ARGUMENTS if argument in cmd
                ]

                if matched_arguments:
                    add_finding(
                        findings,
                        "high",
                        "PROC-004",
                        "Suspicious PowerShell command line",
                        (
                            "PowerShell was launched with arguments "
                            "commonly associated with obfuscated, "
                            "download, or in-memory execution."
                        ),
                        process,
                    )

            if parent_name in OFFICE_PARENT_PROCESSES and name in SCRIPT_OR_SHELL_PROCESSES:
                add_finding(
                    findings,
                    "high",
                    "PROC-005",
                    "Office application spawned script interpreter",
                    (
                        f"{parent_name} spawned {name}. "
                        "This parent-child relationship is "
                        "commonly investigated during malicious "
                        "document analysis."
                    ),
                    process,
                )

            if parent_name in BROWSER_PARENT_PROCESSES and name in {
                "powershell.exe",
                "pwsh.exe",
                "cmd.exe",
                "mshta.exe",
            }:
                add_finding(
                    findings,
                    "medium",
                    "PROC-006",
                    "Browser spawned command interpreter",
                    (f"{parent_name} spawned {name}. This process chain deserves investigation."),
                    process,
                )

            if name == "certutil.exe":
                if any(argument in cmd for argument in CERTUTIL_SUSPICIOUS_ARGUMENTS):
                    add_finding(
                        findings,
                        "medium",
                        "PROC-007",
                        "Suspicious CertUtil usage",
                        ("CertUtil was used with download or decoding-related arguments."),
                        process,
                    )

            if name == "rundll32.exe":
                if any(argument in cmd for argument in RUNDLL32_SUSPICIOUS_ARGUMENTS):
                    add_finding(
                        findings,
                        "high",
                        "PROC-008",
                        "Suspicious Rundll32 usage",
                        (
                            "Rundll32 contains arguments associated "
                            "with remote or script-based execution."
                        ),
                        process,
                    )

            if name == "regsvr32.exe":
                if any(argument in cmd for argument in REGSVR32_SUSPICIOUS_ARGUMENTS):
                    add_finding(
                        findings,
                        "high",
                        "PROC-009",
                        "Suspicious Regsvr32 usage",
                        ("Regsvr32 contains arguments associated with scriptlet-based execution."),
                        process,
                    )

            if name == "mshta.exe":
                if any(argument in cmd for argument in MSHTA_SUSPICIOUS_ARGUMENTS):
                    add_finding(
                        findings,
                        "high",
                        "PROC-010",
                        "Suspicious MSHTA usage",
                        ("MSHTA appears to be executing remote or inline script content."),
                        process,
                    )

            if name == "cmd.exe":
                matched_arguments = [
                    argument for argument in CMD_SUSPICIOUS_ARGUMENTS if argument in cmd
                ]

                if matched_arguments:
                    add_finding(
                        findings,
                        "medium",
                        "PROC-011",
                        "Command shell launching monitored utility",
                        ("cmd.exe contains references to another monitored command-line utility."),
                        process,
                    )

            if name in LOLBINS:
                if executable and "\\temp\\" in executable:
                    add_finding(
                        findings,
                        "high",
                        "PROC-012",
                        "System utility executing from unusual path",
                        (
                            f"{name} is a commonly abused Windows "
                            "utility but is executing from a "
                            "temporary location."
                        ),
                        process,
                    )

        else:
            analyze_linux_process(
                findings,
                process,
                name,
                parent_name,
                executable,
                cmd,
            )

        if process.get("exe_deleted"):
            add_finding(
                findings,
                "medium",
                "DEL-001",
                "Running process has deleted executable",
                (
                    f"{name or 'Unknown process'} is running "
                    "from an executable that was removed from "
                    "disk, a common evasion technique."
                ),
                process,
                mitre={
                    "technique": "T1070.004",
                    "name": "Indicator Removal: File Deletion",
                    "tactic": "Defense Evasion",
                },
            )

    logger.debug(
        "Process detector produced %d finding(s) from %d process(es)",
        len(findings),
        len(processes),
    )

    return findings
