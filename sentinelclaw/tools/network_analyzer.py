import json

import psutil


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

    except psutil.AccessDenied:
        return [
            {
                "error": "Access denied while reading network connections. Try running the terminal as Administrator."
            }
        ]

    return connections


def main() -> None:
    print(json.dumps(get_network_connections(), indent=2))


if __name__ == "__main__":
    main()
