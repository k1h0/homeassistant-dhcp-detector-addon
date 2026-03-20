#!/usr/bin/env python3
"""
Passive DHCP sniffer for Home Assistant presence detection.

Listens for DHCP DISCOVER, REQUEST, and INFORM packets on a raw socket,
matches source MACs against a configured device list, and writes a
timestamp sensor state to Home Assistant via the Supervisor REST API.
"""

import ctypes
import re
import json
import logging
import os
import signal
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
ETHERTYPE_IPV4 = 0x0800
IP_PROTO_UDP = 17
BOOTP_MAGIC_COOKIE = 0x63825363

# DHCP message type option values (option 53)
DHCP_DISCOVER = 1
DHCP_REQUEST = 3
DHCP_INFORM = 8
TRACKED_MSG_TYPES = {DHCP_DISCOVER, DHCP_REQUEST, DHCP_INFORM}
MSG_TYPE_NAMES = {DHCP_DISCOVER: "DISCOVER", DHCP_REQUEST: "REQUEST", DHCP_INFORM: "INFORM"}

# BPF filter equivalent to `tcpdump -dd "udp and (port 67 or port 68)"`.
# Each tuple is (code, jt, jf, k).
BPF_UDP_DHCP = [
    (0x28, 0, 0, 0x0000000c), (0x15, 0, 8, 0x00000800),
    (0x30, 0, 0, 0x00000017), (0x15, 0, 6, 0x00000011),
    (0x28, 0, 0, 0x00000014), (0x45, 4, 0, 0x00001fff),
    (0xb1, 0, 0, 0x0000000e), (0x48, 0, 0, 0x00000000),
    (0x15, 1, 0, 0x00000043), (0x15, 0, 1, 0x00000044),
    (0x06, 0, 0, 0x00040000), (0x06, 0, 0, 0x00000000),
]

SOL_SOCKET = 1
SO_ATTACH_FILTER = 26


def attach_bpf(sock: socket.socket) -> None:
    """Attach a BPF filter to *sock* restricting delivery to UDP port 67/68.

    Uses ctypes to build the ``sock_fprog`` structure expected by
    ``setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, ...)``.  On failure logs a
    WARNING and returns without aborting startup.
    """
    # sock_filter: array of { __u16 code, __u8 jt, __u8 jf, __u32 k }
    n = len(BPF_UDP_DHCP)
    insn_bytes = b"".join(
        struct.pack("HBBI", code, jt, jf, k)
        for code, jt, jf, k in BPF_UDP_DHCP
    )
    insn_array = ctypes.create_string_buffer(insn_bytes)

    # sock_fprog: { __u16 len, [padding], ptr filter }
    # Pack manually to match kernel ABI on both 32-bit and 64-bit.
    ptr = ctypes.addressof(insn_array)
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        prog_bytes = struct.pack("H6xQ", n, ptr)
    else:
        prog_bytes = struct.pack("H2xI", n, ptr)

    try:
        sock.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, prog_bytes)
        logging.info("BPF filter attached — receiving UDP port 67/68 only")
    except OSError as exc:
        logging.warning(
            "BPF filter could not be attached, falling back to unfiltered capture: %s", exc
        )


# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------

def parse_dhcp_packet(data: bytes):
    """Parse a raw Ethernet frame.

    Returns ``(mac_str, dhcp_message_type)`` for valid DHCP client packets,
    or ``None`` if the frame is not a DHCP client packet.
    """
    # --- Ethernet header (14 bytes) ---
    if len(data) < 14:
        return None
    ethertype = struct.unpack_from("!H", data, 12)[0]
    if ethertype != ETHERTYPE_IPV4:
        return None

    # --- IPv4 header ---
    ip_start = 14
    if len(data) < ip_start + 20:
        return None
    ip_ihl = (data[ip_start] & 0x0F) * 4
    ip_proto = data[ip_start + 9]
    if ip_proto != IP_PROTO_UDP:
        return None

    # --- UDP header (8 bytes) ---
    udp_start = ip_start + ip_ihl
    if len(data) < udp_start + 8:
        return None
    src_port = struct.unpack_from("!H", data, udp_start)[0]
    dst_port = struct.unpack_from("!H", data, udp_start + 2)[0]
    if src_port != DHCP_CLIENT_PORT or dst_port != DHCP_SERVER_PORT:
        return None

    # --- BOOTP / DHCP payload ---
    # Fixed BOOTP header: 236 bytes; magic cookie: 4 bytes → 240 bytes minimum.
    bootp_start = udp_start + 8
    if len(data) < bootp_start + 240:
        return None

    # op == 1: BOOTREQUEST (client → server)
    if data[bootp_start] != 1:
        return None

    # Client hardware address (MAC) is at offset 28 inside BOOTP, 6 bytes.
    mac_start = bootp_start + 28
    mac_bytes = data[mac_start : mac_start + 6]
    mac = ":".join(f"{b:02x}" for b in mac_bytes)

    # Validate magic cookie.
    magic = struct.unpack_from("!I", data, bootp_start + 236)[0]
    if magic != BOOTP_MAGIC_COOKIE:
        return None

    # --- Parse DHCP options to find message type (option 53) ---
    dhcp_type = None
    idx = bootp_start + 240
    end = len(data)
    while idx < end:
        opt_code = data[idx]
        if opt_code == 255:  # End
            break
        if opt_code == 0:    # Pad
            idx += 1
            continue
        if idx + 1 >= end:
            break
        opt_len = data[idx + 1]
        if idx + 2 + opt_len > end:
            break
        if opt_code == 53 and opt_len == 1:
            dhcp_type = data[idx + 2]
        idx += 2 + opt_len

    if dhcp_type is None:
        return None

    return mac, dhcp_type


# ---------------------------------------------------------------------------
# Home Assistant Supervisor API
# ---------------------------------------------------------------------------

HA_STATE_URL = "http://supervisor/homeassistant/api/states/sensor.dhcp_last_seen_{dev_id}"


def update_sensor(token: str, mac: str, name: str) -> bool:
    """POST a timestamp sensor state to HA via the Supervisor proxy.

    Creates or updates ``sensor.dhcp_last_seen_<dev_id>`` with the current
    local time as the state value (ISO 8601 with timezone offset).

    Returns True on success, False on error.
    """
    # Sanitize name → valid HA entity ID segment (lowercase, only a-z/0-9/_).
    dev_id = re.sub(r"[^a-z0-9_]", "_", name.lower()).strip("_")
    timestamp = datetime.now().astimezone().isoformat()
    payload = json.dumps({
        "state": timestamp,
        "attributes": {
            "device_class": "timestamp",
            "friendly_name": f"DHCP Last Seen {name}",  # human-readable, unchanged
            "mac": mac,
        },
    }).encode()
    url = HA_STATE_URL.format(dev_id=dev_id)  # use sanitized dev_id in the URL
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 201)
    except urllib.error.HTTPError as exc:
        logging.error("HTTP error updating sensor for %s (%s): %s %s", name, mac, exc.code, exc.reason)
    except urllib.error.URLError as exc:
        logging.error("URL error updating sensor for %s (%s): %s", name, mac, exc.reason)
    except OSError as exc:
        logging.error("Error updating sensor for %s (%s): %s", name, mac, exc)
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )

    # Load add-on options written by the Supervisor.
    options_path = "/data/options.json"
    try:
        with open(options_path) as fh:
            options = json.load(fh)
    except FileNotFoundError:
        logging.error("Options file not found: %s", options_path)
        sys.exit(1)

    interface = options.get("interface", "eth0")
    devices = options.get("devices", [])

    token = os.environ.get("SUPERVISOR_TOKEN", "")
    if not token:
        logging.error("SUPERVISOR_TOKEN environment variable is not set. "
                      "Ensure homeassistant_api is enabled in config.yaml.")
        sys.exit(1)

    # Build MAC → friendly-name mapping; normalise MACs to lowercase colon-separated.
    device_map: dict[str, str] = {}
    for dev in devices:
        mac = dev["mac"].lower().replace("-", ":").strip()
        device_map[mac] = dev["name"]

    logging.info("DHCP Detector starting — interface=%s, tracking %d device(s)",
                 interface, len(device_map))
    for mac, name in device_map.items():
        logging.info("  tracking: %s → %s (sensor.dhcp_last_seen_%s)", mac, name, name)

    stop_event = threading.Event()

    def handle_shutdown_signal(signum, frame):
        logging.info("Received signal %s — shutting down.", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_shutdown_signal)
    signal.signal(signal.SIGINT, handle_shutdown_signal)

    # Open a raw AF_PACKET socket bound to the chosen interface.
    # AF_PACKET operates at Ethernet layer 2 and does NOT bind to any UDP/TCP
    # port, so it never interferes with the existing DHCP server on ports 67/68.
    # A 1-second receive timeout keeps the loop interruptible by signals.
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_IPV4))
        sock.settimeout(1.0)
        sock.bind((interface, 0))
    except PermissionError:
        logging.error("Permission denied opening raw socket. Ensure CAP_NET_RAW is granted.")
        sys.exit(1)
    except OSError as exc:
        logging.error("Failed to open raw socket on %s: %s", interface, exc)
        sys.exit(1)

    attach_bpf(sock)

    logging.info("Listening on %s …", interface)

    while not stop_event.is_set():
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            # No packet in the last second — loop back and check stop_event.
            continue
        except OSError as exc:
            logging.error("Socket read error: %s", exc)
            time.sleep(1)
            continue

        result = parse_dhcp_packet(data)
        if result is None:
            continue

        mac, dhcp_type = result
        if dhcp_type not in TRACKED_MSG_TYPES:
            continue
        if mac not in device_map:
            continue

        name = device_map[mac]
        # Derive the sanitized entity ID the same way update_sensor does.
        dev_id = re.sub(r"[^a-z0-9_]", "_", name.lower()).strip("_")
        type_name = MSG_TYPE_NAMES.get(dhcp_type, str(dhcp_type))
        logging.info(
            "%s  DHCP %-8s  %s (%s) → sensor.dhcp_last_seen_%s",
            time.strftime("%Y-%m-%d %H:%M:%S"),
            type_name,
            name,
            mac,
            dev_id,  # log the actual entity ID that will be written
        )

        update_sensor(token, mac, name)

    sock.close()
    logging.info("DHCP Detector stopped.")


if __name__ == "__main__":
    main()
