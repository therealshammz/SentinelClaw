EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".cpl",
    ".msi",
}

SCRIPT_EXTENSIONS = {
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
}

SUSPICIOUS_DOUBLE_EXTENSIONS = {
    ".pdf.exe",
    ".doc.exe",
    ".docx.exe",
    ".jpg.exe",
    ".jpeg.exe",
    ".png.exe",
    ".txt.exe",
}

USER_WRITABLE_LOCATIONS = [
    "\\downloads\\",
    "\\temp\\",
    "\\appdata\\local\\temp\\",
]


def analyze_file_findings(
    file_info: dict,
) -> list[dict]:

    findings: list[dict] = []

    if "error" in file_info:
        return findings

    path = (
        file_info.get("path")
        or ""
    ).lower()

    name = (
        file_info.get("name")
        or ""
    ).lower()

    extension = (
        file_info.get("extension")
        or ""
    ).lower()

    entropy = file_info.get(
        "entropy",
        0.0,
    )

    authenticode = (
        file_info.get("authenticode")
        or {}
    )

    signature_status = (
        authenticode.get("status")
        or ""
    ).lower()

    if any(
        name.endswith(double_extension)
        for double_extension
        in SUSPICIOUS_DOUBLE_EXTENSIONS
    ):
        findings.append(
            {
                "severity": "high",
                "rule_id": "FILE-001",
                "title": "Suspicious double file extension",
                "description": (
                    "The filename uses a double extension "
                    "that may disguise an executable file."
                ),
                "evidence": {
                    "path": file_info.get("path"),
                    "sha256": file_info.get("sha256"),
                },
            }
        )

    if (
        extension in EXECUTABLE_EXTENSIONS
        and any(
            location in path
            for location
            in USER_WRITABLE_LOCATIONS
        )
    ):
        findings.append(
            {
                "severity": "low",
                "rule_id": "FILE-002",
                "title": "Executable in user-writable directory",
                "description": (
                    "The executable is stored in a location "
                    "commonly writable by the current user."
                ),
                "evidence": {
                    "path": file_info.get("path"),
                    "sha256": file_info.get("sha256"),
                },
            }
        )

    if (
        file_info.get("is_pe_file")
        and signature_status
        in {
            "notsigned",
            "unknownerror",
            "hashmismatch",
            "nottrusted",
        }
    ):
        findings.append(
            {
                "severity": "low",
                "rule_id": "FILE-003",
                "title": "PE file is not trusted by Authenticode",
                "description": (
                    "Windows did not report a valid trusted "
                    "Authenticode signature for this PE file."
                ),
                "evidence": {
                    "status": authenticode.get("status"),
                    "status_message": authenticode.get(
                        "status_message"
                    ),
                    "signer": authenticode.get("signer"),
                    "sha256": file_info.get("sha256"),
                },
            }
        )

    if (
        file_info.get("is_pe_file")
        and entropy >= 7.2
    ):
        findings.append(
            {
                "severity": "medium",
                "rule_id": "FILE-004",
                "title": "High-entropy executable",
                "description": (
                    "The executable has high byte entropy. "
                    "Packed, compressed, or encrypted binaries "
                    "can exhibit this characteristic."
                ),
                "evidence": {
                    "entropy": entropy,
                    "sha256": file_info.get("sha256"),
                },
            }
        )

    if extension in SCRIPT_EXTENSIONS:
        findings.append(
            {
                "severity": "info",
                "rule_id": "FILE-005",
                "title": "Script file analyzed",
                "description": (
                    "The analyzed file is a script. "
                    "Script contents may require additional "
                    "static analysis."
                ),
                "evidence": {
                    "extension": extension,
                    "path": file_info.get("path"),
                },
            }
        )

    return findings
