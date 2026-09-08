import ipaddress


SUSPICIOUS_PORTS = {
    23: "Telnet",
    4444: "Common reverse-shell/metasploit port",
    5555: "Common Android ADB/debugging port",
    6667: "Common IRC port",
}


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

        remote = connection.get("remote_address")

        if not remote:
            continue

        remote_ip = remote.get("ip")
        remote_port = remote.get("port")
        pid = connection.get("pid")
        status = connection.get("status")

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

    return findings
