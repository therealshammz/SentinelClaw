import argparse
import json
from pathlib import Path


SUSPICIOUS_KEYWORDS = [
    "failed login",
    "authentication failed",
    "unauthorized",
    "access denied",
    "malware",
    "ransomware",
    "powershell",
    "encodedcommand",
    "mimikatz",
    "brute force",
    "privilege escalation",
]


def analyze_log_file(file_path: str) -> dict:
    path = Path(file_path)

    if not path.exists():
        return {
            "error": f"File not found: {file_path}"
        }

    if not path.is_file():
        return {
            "error": f"Not a file: {file_path}"
        }

    matches = []
    total_lines = 0

    with path.open("r", encoding="utf-8", errors="ignore") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            total_lines += 1
            lower_line = line.lower()

            matched_keywords = [
                keyword
                for keyword in SUSPICIOUS_KEYWORDS
                if keyword in lower_line
            ]

            if matched_keywords:
                matches.append(
                    {
                        "line_number": line_number,
                        "matched_keywords": matched_keywords,
                        "text": line.strip(),
                    }
                )

    return {
        "file": str(path),
        "total_lines": total_lines,
        "suspicious_matches": len(matches),
        "matches": matches,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a text log file for suspicious keywords."
    )

    parser.add_argument(
        "file",
        help="Path to the log file to analyze",
    )

    args = parser.parse_args()

    result = analyze_log_file(args.file)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
