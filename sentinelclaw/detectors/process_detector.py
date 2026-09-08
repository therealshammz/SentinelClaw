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


def command_line_text(process: dict) -> str:
    command_line = process.get("command_line") or []

    if isinstance(command_line, str):
        return command_line.lower()

    return " ".join(
        str(item)
        for item in command_line
    ).lower()


def add_finding(
    findings: list[dict],
    severity: str,
    rule_id: str,
    title: str,
    description: str,
    process: dict,
) -> None:
    findings.append(
        {
            "severity": severity,
            "rule_id": rule_id,
            "title": title,
            "description": description,
            "pid": process.get("pid"),
            "process_name": process.get("name"),
            "parent_name": process.get("parent_name"),
            "evidence": {
                "executable": process.get("executable"),
                "command_line": process.get("command_line"),
                "ppid": process.get("ppid"),
                "create_time": process.get("create_time"),
            },
        }
    )


def analyze_processes(
    processes: list[dict],
) -> list[dict]:

    findings = []

    for process in processes:

        name = (
            process.get("name")
            or ""
        ).lower()

        parent_name = (
            process.get("parent_name")
            or ""
        ).lower()

        executable = (
            process.get("executable")
            or ""
        ).lower()

        cmd = command_line_text(process)

        if name in HIGH_RISK_TOOL_NAMES:
            add_finding(
                findings,
                "high",
                "PROC-001",
                "High-risk security tool detected",
                (
                    f"{name} matches a monitored "
                    "credential or process-dumping tool."
                ),
                process,
            )

        if (
            executable
            and any(
                directory in executable
                for directory in SUSPICIOUS_DIRECTORIES
            )
        ):
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

        if not executable:
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

        if name in {
            "powershell.exe",
            "pwsh.exe",
        }:
            matched_arguments = [
                argument
                for argument
                in POWERSHELL_SUSPICIOUS_ARGUMENTS
                if argument in cmd
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

        if (
            parent_name in OFFICE_PARENT_PROCESSES
            and name in SCRIPT_OR_SHELL_PROCESSES
        ):
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

        if (
            parent_name in BROWSER_PARENT_PROCESSES
            and name in {
                "powershell.exe",
                "pwsh.exe",
                "cmd.exe",
                "mshta.exe",
            }
        ):
            add_finding(
                findings,
                "medium",
                "PROC-006",
                "Browser spawned command interpreter",
                (
                    f"{parent_name} spawned {name}. "
                    "This process chain deserves investigation."
                ),
                process,
            )

        if name == "certutil.exe":
            if any(
                argument in cmd
                for argument
                in CERTUTIL_SUSPICIOUS_ARGUMENTS
            ):
                add_finding(
                    findings,
                    "medium",
                    "PROC-007",
                    "Suspicious CertUtil usage",
                    (
                        "CertUtil was used with download or "
                        "decoding-related arguments."
                    ),
                    process,
                )

        if name == "rundll32.exe":
            if any(
                argument in cmd
                for argument
                in RUNDLL32_SUSPICIOUS_ARGUMENTS
            ):
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
            if any(
                argument in cmd
                for argument
                in REGSVR32_SUSPICIOUS_ARGUMENTS
            ):
                add_finding(
                    findings,
                    "high",
                    "PROC-009",
                    "Suspicious Regsvr32 usage",
                    (
                        "Regsvr32 contains arguments associated "
                        "with scriptlet-based execution."
                    ),
                    process,
                )

        if name == "mshta.exe":
            if any(
                argument in cmd
                for argument
                in MSHTA_SUSPICIOUS_ARGUMENTS
            ):
                add_finding(
                    findings,
                    "high",
                    "PROC-010",
                    "Suspicious MSHTA usage",
                    (
                        "MSHTA appears to be executing remote "
                        "or inline script content."
                    ),
                    process,
                )

        if name == "cmd.exe":
            matched_arguments = [
                argument
                for argument
                in CMD_SUSPICIOUS_ARGUMENTS
                if argument in cmd
            ]

            if matched_arguments:
                add_finding(
                    findings,
                    "medium",
                    "PROC-011",
                    "Command shell launching monitored utility",
                    (
                        "cmd.exe contains references to another "
                        "monitored command-line utility."
                    ),
                    process,
                )

        if name in LOLBINS:
            if (
                executable
                and "\\temp\\" in executable
            ):
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

    return findings
