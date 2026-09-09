import hashlib
import json
import logging
import math
import mimetypes
import os
import subprocess
from collections import Counter
from pathlib import Path

logger = logging.getLogger(
    __name__
)


def calculate_sha256(path: Path) -> str:
    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            sha256.update(chunk)

    return sha256.hexdigest()


def calculate_entropy(path: Path) -> float:
    try:
        data = path.read_bytes()
    except OSError as exc:
        logger.warning(
            "Unable to read %s for entropy "
            "calculation: %s",
            path,
            exc,
        )

        return 0.0

    if not data:
        return 0.0

    byte_counts = Counter(data)
    length = len(data)

    entropy = 0.0

    for count in byte_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def is_pe_file(path: Path) -> bool:
    try:
        with path.open("rb") as file:
            return file.read(2) == b"MZ"
    except OSError as exc:
        logger.debug(
            "Unable to probe PE signature for %s: %s",
            path,
            exc,
        )

        return False


def get_authenticode_status(path: Path) -> dict:
    escaped_path = str(path).replace("'", "''")

    command = (
        "Get-AuthenticodeSignature "
        f"-LiteralPath '{escaped_path}' "
        "| Select-Object Status,StatusMessage,"
        "@{Name='SignerCertificate';"
        "Expression={$_.SignerCertificate.Subject}} "
        "| ConvertTo-Json -Compress"
    )

    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        if completed.returncode != 0:
            return {
                "status": "Unknown",
                "status_message": completed.stderr.strip(),
                "signer": None,
            }

        output = completed.stdout.strip()

        if not output:
            return {
                "status": "Unknown",
                "status_message": "No signature information returned.",
                "signer": None,
            }

        data = json.loads(output)

        return {
            "status": data.get("Status"),
            "status_message": data.get("StatusMessage"),
            "signer": data.get("SignerCertificate"),
        }

    except Exception as exc:
        return {
            "status": "Unknown",
            "status_message": str(exc),
            "signer": None,
        }


def analyze_file(file_path: str) -> dict:
    path = Path(file_path).expanduser()

    if not path.exists():
        return {
            "error": f"File not found: {file_path}"
        }

    if not path.is_file():
        return {
            "error": f"Not a file: {file_path}"
        }

    try:
        stat = path.stat()
    except OSError as exc:
        return {
            "error": str(exc)
        }

    mime_type, _ = mimetypes.guess_type(path.name)

    pe_file = is_pe_file(path)

    result = {
        "path": str(path.resolve()),
        "name": path.name,
        "extension": path.suffix.lower(),
        "size_bytes": stat.st_size,
        "size_mb": round(
            stat.st_size / (1024 * 1024),
            3,
        ),
        "mime_type": mime_type,
        "sha256": calculate_sha256(path),
        "entropy": calculate_entropy(path),
        "is_pe_file": pe_file,
        "authenticode": None,
    }

    if os.name == "nt" and pe_file:
        result["authenticode"] = get_authenticode_status(path)

    logger.debug(
        "Analyzed %s (%d bytes, entropy %.4f)",
        path.name,
        stat.st_size,
        result.get("entropy", 0.0),
    )

    return result


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Analyze a local file."
    )

    parser.add_argument(
        "file",
        help="Path to the file to analyze",
    )

    args = parser.parse_args()

    print(
        json.dumps(
            analyze_file(args.file),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
