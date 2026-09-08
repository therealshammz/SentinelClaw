from scapy.all import IP, TCP, UDP, wrpcap


packets = []


# Simulated TCP port scan:
# one source contacts many ports on one destination
for port in range(20, 50):
    packets.append(
        IP(
            src="192.168.56.10",
            dst="192.168.56.20",
        )
        / TCP(
            sport=40000 + port,
            dport=port,
            flags="S",
        )
    )


# Traffic to monitored port 4444
packets.append(
    IP(
        src="192.168.56.10",
        dst="192.168.56.30",
    )
    / TCP(
        sport=50000,
        dport=4444,
        flags="S",
    )
)


# Normal HTTPS traffic
for _ in range(10):
    packets.append(
        IP(
            src="192.168.56.10",
            dst="8.8.8.8",
        )
        / TCP(
            sport=51000,
            dport=443,
            flags="A",
        )
    )


# Some UDP traffic
for port in range(1000, 1005):
    packets.append(
        IP(
            src="192.168.56.10",
            dst="192.168.56.40",
        )
        / UDP(
            sport=53000,
            dport=port,
        )
    )


output_path = (
    r"data\pcaps\sentinelclaw_test.pcap"
)

wrpcap(
    output_path,
    packets,
)

print(
    f"Created {output_path}"
)
print(
    f"Packets: {len(packets)}"
)
