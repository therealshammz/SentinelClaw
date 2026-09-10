from sentinelclaw.config.constants import (
    SEVERITY_ORDER,
    SEVERITY_RANK,
)
from sentinelclaw.detectors.network_detector import (
    SUSPICIOUS_PORTS,
)
from sentinelclaw.detectors.pcap_detector import (
    MONITORED_PORTS,
)


def test_severity_order_is_canonical_ascending() -> None:
    assert SEVERITY_ORDER == (
        "info",
        "low",
        "medium",
        "high",
        "critical",
    )

    assert SEVERITY_RANK["info"] < SEVERITY_RANK["low"]
    assert SEVERITY_RANK["low"] < SEVERITY_RANK["medium"]
    assert SEVERITY_RANK["medium"] < SEVERITY_RANK["high"]
    assert SEVERITY_RANK["high"] < SEVERITY_RANK["critical"]


def test_monitored_port_list_is_shared() -> None:
    assert SUSPICIOUS_PORTS is MONITORED_PORTS

    assert set(MONITORED_PORTS) == {
        23,
        4444,
        5555,
        6667,
    }
