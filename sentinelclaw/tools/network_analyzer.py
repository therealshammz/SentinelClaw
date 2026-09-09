import json
import logging

import psutil

logger = logging.getLogger(
    __name__
)


def format_address(address):
    if not address:
        return None

    return {
        "ip": address.ip,
        "port": address.port,
    }


def get_network_connections() -> list[dict]:
    connections = []

    try:
        for connection in psutil.net_connections(kind="inet"):
            connections.append(
                {
                    "local_address": format_address(connection.laddr),
                    "remote_address": format_address(connection.raddr),
                    "status": connection.status,
                    "pid": connection.pid,
                    "family": str(connection.family),
                    "type": str(connection.type),
                }
            )

    except psutil.AccessDenied as exc:
        logger.warning(
            "Network connection collection denied: %s",
            exc,
        )

        return [
            {
                "error": "Access denied while reading network connections. Try running the terminal as Administrator."
            }
        ]

    logger.debug(
        "Collected %d network connection(s)",
        len(connections),
    )

    return connections


def main() -> None:
    print(json.dumps(get_network_connections(), indent=2))


if __name__ == "__main__":
    main()
