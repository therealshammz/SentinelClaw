import json
import logging
import platform
import socket

import psutil

logger = logging.getLogger(
    __name__
)


def get_system_info() -> dict:
    logger.debug(
        "Collecting system information..."
    )

    memory = psutil.virtual_memory()

    info = {
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "physical_cpu_cores": psutil.cpu_count(logical=False),
        "logical_cpu_cores": psutil.cpu_count(logical=True),
        "total_ram_gb": round(memory.total / (1024 ** 3), 2),
        "available_ram_gb": round(memory.available / (1024 ** 3), 2),
        "ram_usage_percent": memory.percent,
        "boot_time": psutil.boot_time(),
    }

    logger.debug(
        "Collected system information "
        "for %s",
        info.get("hostname"),
    )

    return info


def main() -> None:
    print(json.dumps(get_system_info(), indent=2))


if __name__ == "__main__":
    main()
