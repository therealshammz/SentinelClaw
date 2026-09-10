import ipaddress
import logging

from sentinelclaw.config.constants import (
    MONITORED_PORTS as SUSPICIOUS_PORTS,
)

logger = logging.getLogger(
    __name__
)

# Well-known service ports that are routinely bound locally; listening
# sockets on these are considered standard and are not flagged.
KNOWN_SERVICE_PORTS = frozenset(
    {
        2049,
        2375,
        2376,
        3000,
        3306,
        5000,
        5353,
        5432,
        6379,
        8000,
        8080,
        8443,
        9000,
        9090,
        9200,
        11211,
        27017,
    }
)


def is_public_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)

        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        )

    except ValueError:
        return False


def analyze_network(connections: list[dict]) -> list[dict]:
    findings = []

    for connection in connections:

        if "error" in connection:
            continue

        pid = connection.get("pid")
        status = connection.get("status")

        # Flag TCP listeners bound to non-standard ports; unusual
        # listening sockets can indicate backdoors or rogue services.
        local = connection.get("local_address")

        if local:
            local_port = local.get("port")

            connection_type = str(
                connection.get("type") or ""
            )

            if (
                status == "LISTEN"
                and "SOCK_STREAM" in connection_type
                and local_port is not None
                and local_port > 1024
                and local_port not in KNOWN_SERVICE_PORTS
            ):
                findings.append(
                    {
                        "severity": "low",
                        "rule_id": "NET-LISTEN-001",
                        "title": (
                            "Listening socket on non-standard port"
                        ),
                        "description": (
                            f"Process {pid or 'unknown'} is listening "
                            f"on non-standard port {local_port}."
                        ),
                        "pid": pid,
                        "local_ip": local.get("ip"),
                        "local_port": local_port,
                        "status": status,
                    }
                )

        remote = connection.get("remote_address")

        if not remote:
            continue

        remote_ip = remote.get("ip")
        remote_port = remote.get("port")

        # Detect connections involving monitored ports.
        if remote_port in SUSPICIOUS_PORTS:
            findings.append(
                {
                    "severity": "medium",
                    "rule_id": "NET-001",
                    "title": "Connection using monitored port",
                    "description": (
                        f"Connection uses remote port {remote_port} "
                        f"({SUSPICIOUS_PORTS[remote_port]})."
                    ),
                    "pid": pid,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": status,
                }
            )

        # Record established connections to public IP addresses.
        if (
            remote_ip
            and is_public_ip(remote_ip)
            and status == "ESTABLISHED"
        ):
            findings.append(
                {
                    "severity": "info",
                    "rule_id": "NET-002",
                    "title": "Established public network connection",
                    "description": (
                        "A process currently has an established "
                        "connection to a public IP address."
                    ),
                    "pid": pid,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": status,
                }
            )

    logger.debug(
        "Network detector produced %d finding(s) "
        "from %d connection(s)",
        len(findings),
        len(connections),
    )

    return findings
