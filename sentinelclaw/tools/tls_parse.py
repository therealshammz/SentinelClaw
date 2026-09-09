"""
Pure payload-level protocol parsers (P4-21).

These helpers decode application payloads without scapy so they stay
unit-testable on canned byte strings and importable in any install:

* ``extract_sni_from_client_hello`` walks a TLS ClientHello record
  (RFC 8446/6066) looking for the ``server_name`` extension.
* ``decode_dns_qname`` converts a DNS wire-format query name into a
  normalized lowercase string.

Every function is defensive: malformed or truncated input yields
``None`` (or an empty result) instead of raising.
"""

from __future__ import annotations

TLS_HANDSHAKE_RECORD = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_EXTENSION_SERVER_NAME = 0x0000


def extract_sni_from_client_hello(
    payload: bytes,
) -> str | None:
    """Extract the SNI hostname from a TLS ClientHello, if present.

    Parses the outermost TLS record and handshake framing manually so
    no optional TLS layer (or its crypto dependencies) is required.
    Returns ``None`` when the payload is not a ClientHello, does not
    carry a ``server_name`` extension, or is truncated/malformed.
    """
    if len(payload) < 5:
        return None

    if payload[0] != TLS_HANDSHAKE_RECORD:
        return None

    record_length = int.from_bytes(
        payload[3:5],
        "big",
    )

    handshake = payload[5 : 5 + record_length]

    if len(handshake) < 4:
        return None

    if handshake[0] != TLS_HANDSHAKE_CLIENT_HELLO:
        return None

    handshake_length = int.from_bytes(
        handshake[1:4],
        "big",
    )

    hello = handshake[4 : 4 + handshake_length]

    # ClientHello fixed header: legacy_version(2) + random(32).
    if len(hello) < 34:
        return None

    cursor = 34

    if len(hello) < cursor + 1:
        return None

    session_id_length = hello[cursor]
    cursor += 1

    if len(hello) < cursor + session_id_length:
        return None

    cursor += session_id_length

    if len(hello) < cursor + 2:
        return None

    cipher_count = int.from_bytes(
        hello[cursor : cursor + 2],
        "big",
    )

    cursor += 2

    if (
        cipher_count % 2
        or len(hello) < cursor + cipher_count
    ):
        return None

    cursor += cipher_count

    if len(hello) < cursor + 1:
        return None

    compression_count = hello[cursor]
    cursor += 1

    if len(hello) < cursor + compression_count:
        return None

    cursor += compression_count

    if len(hello) < cursor + 2:
        return None

    extensions_length = int.from_bytes(
        hello[cursor : cursor + 2],
        "big",
    )

    extension_start = cursor + 2
    extension_end = extension_start + extensions_length

    if extension_end > len(hello):
        return None

    cursor = extension_start

    while cursor + 4 <= extension_end:
        extension_type = int.from_bytes(
            hello[cursor : cursor + 2],
            "big",
        )

        extension_length = int.from_bytes(
            hello[cursor + 2 : cursor + 4],
            "big",
        )

        cursor += 4

        if cursor + extension_length > extension_end:
            return None

        if extension_type == TLS_EXTENSION_SERVER_NAME:
            return _parse_server_name_list(
                hello[cursor : cursor + extension_length]
            )

        cursor += extension_length

    return None


def _parse_server_name_list(
    data: bytes,
) -> str | None:
    if len(data) < 2:
        return None

    if len(data) < 2 + int.from_bytes(
        data[0:2],
        "big",
    ):
        return None

    cursor = 2

    while cursor + 3 <= len(data):
        name_type = data[cursor]
        name_length = int.from_bytes(
            data[cursor + 1 : cursor + 3],
            "big",
        )

        cursor += 3

        if cursor + name_length > len(data):
            return None

        if name_type == 0:
            return _clean_hostname(
                data[cursor : cursor + name_length]
            )

        cursor += name_length

    return None


def _clean_hostname(
    raw: bytes,
) -> str | None:
    try:
        hostname = raw.decode(
            "utf-8",
            errors="replace",
        )
    except Exception:
        return None

    hostname = hostname.strip().rstrip(".")

    if not hostname:
        return None

    if len(hostname) > 253:
        return None

    if any(
        character.isspace()
        or ord(character) < 0x21
        or ord(character) > 0x7E
        for character in hostname
    ):
        return None

    return hostname.lower()


def decode_dns_qname(
    raw: bytes,
) -> str | None:
    """Decode a DNS query name into a lowercase string.

    Accepts both wire-format names (length-prefixed labels, as stored
    on the wire) and the dotted-form bytes scapy exposes on dissected
    packets (e.g. ``b"update.example.xyz."``). Compression pointers are
    not handled; malformed input returns ``None``.
    """
    if not raw:
        return None

    name: str | None = None

    if raw[0] <= 0x3F:
        name = _decode_wire_qname(raw)

    if name is None:
        name = _decode_dotted_qname(raw)

    return name


def _decode_wire_qname(
    raw: bytes,
) -> str | None:
    labels: list[str] = []

    cursor = 0

    while cursor < len(raw):
        length = raw[cursor]

        if length == 0:
            break

        if length & 0xC0:
            return None

        cursor += 1

        if cursor + length > len(raw):
            return None

        labels.append(
            raw[cursor : cursor + length].decode(
                "utf-8",
                errors="replace",
            )
        )

        cursor += length

    if not labels:
        return None

    name = ".".join(labels).lower()

    if len(name) > 253:
        return None

    return name


def _decode_dotted_qname(
    raw: bytes,
) -> str | None:
    text = raw.decode(
        "utf-8",
        errors="replace",
    ).strip().rstrip(".")

    if not text:
        return None

    if "\x00" in text:
        return None

    if any(
        character.isspace()
        or ord(character) < 0x21
        or ord(character) > 0x7E
        for character in text
    ):
        return None

    if not all(
        label
        for label in text.split(".")
    ):
        return None

    name = text.lower()

    if len(name) > 253:
        return None

    return name
