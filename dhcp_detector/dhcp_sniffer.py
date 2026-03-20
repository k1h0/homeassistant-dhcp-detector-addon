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
# Diagnostics counters
# ---------------------------------------------------------------------------

class DiagCounters:
    """Thread-safe counters for diagnostic packet tracing."""

    __slots__ = (
        "_lock",
        "received",
        "drop_too_short",
        "drop_ethertype",
        "drop_not_ipv4",
        "drop_not_udp",
        "drop_udp_truncated",
        "drop_ports",
        "drop_bootp_len",
        "drop_not_bootrequest",
        "drop_magic_cookie",
        "drop_no_opt53",
        "drop_msg_type",
        "drop_mac_not_tracked",
        "matched",
    )

    def __init__(self):
        self._lock = threading.Lock()
        for slot in self.__slots__[1:]:
            setattr(self, slot, 0)

    def inc(self, name: str) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + 1)

    def snapshot(self) -> dict:
        with self._lock:
            return {s: getattr(self, s) for s in self.__slots__[1:]}


_counters = DiagCounters()


def _diag_summary_thread(stop_event: threading.Event, interval: int = 30) -> None:
    """Periodically log a one-line diagnostic summary at DEBUG level."""
    while not stop_event.wait(interval):
        snap = _counters.snapshot()
        logging.debug(
            "diag: recv=%d short=%d etype=%d ipv4=%d udp=%d udp_trunc=%d ports=%d "
            "bootp=%d bootreq=%d cookie=%d opt53=%d msgtype=%d mac=%d matched=%d",
            snap["received"],
            snap["drop_too_short"],
            snap["drop_ethertype"],
            snap["drop_not_ipv4"],
            snap["drop_not_udp"],
            snap["drop_udp_truncated"],
            snap["drop_ports"],
            snap["drop_bootp_len"],
            snap["drop_not_bootrequest"],
            snap["drop_magic_cookie"],
            snap["drop_no_opt53"],
            snap["drop_msg_type"],
            snap["drop_mac_not_tracked"],
            snap["matched"],
        )

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


def sanitize_dev_id(name: str) -> str:  # extracted from duplicated inline expressions
    """Convert a friendly device name to a valid HA entity ID segment."""
    return re.sub(r"[^a-z0-9_]", "_", name.lower()).strip("_")


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

    Diagnostic counters in ``_counters`` are incremented at each rejection
    stage so that the periodic summary can report where frames are being
    dropped.
    """
    _counters.inc("received")

    # --- Ethernet header (14 bytes) ---
    if len(data) < 14:
        _counters.inc("drop_too_short")
        logging.debug("drop: frame too short (%d bytes)", len(data))
        return None
    ethertype = struct.unpack_from("!H", data, 12)[0]
    if ethertype != ETHERTYPE_IPV4:
        _counters.inc("drop_ethertype")
        logging.debug("drop: ethertype=0x%04x (not IPv4)", ethertype)
        return None

    # --- IPv4 header ---
    ip_start = 14
    if len(data) < ip_start + 20:
        _counters.inc("drop_not_ipv4")
        logging.debug("drop: IPv4 header truncated")
        return None
    ip_ihl = (data[ip_start] & 0x0F) * 4
    ip_proto = data[ip_start + 9]
    if ip_proto != IP_PROTO_UDP:
        _counters.inc("drop_not_udp")
        logging.debug("drop: IP proto=%d (not UDP)", ip_proto)
        return None

    # --- UDP header (8 bytes) ---
    udp_start = ip_start + ip_ihl
    if len(data) < udp_start + 8:
        _counters.inc("drop_udp_truncated")
        logging.debug("drop: UDP header truncated")
        return None
    src_port = struct.unpack_from("!H", data, udp_start)[0]
    dst_port = struct.unpack_from("!H", data, udp_start + 2)[0]
    if src_port != DHCP_CLIENT_PORT or dst_port != DHCP_SERVER_PORT:
        _counters.inc("drop_ports")
        logging.debug("drop: UDP ports %d→%d (need 68→67)", src_port, dst_port)
        return None

    # --- BOOTP / DHCP payload ---
    # Fixed BOOTP header: 236 bytes; magic cookie: 4 bytes → 240 bytes minimum.
    bootp_start = udp_start + 8
    if len(data) < bootp_start + 240:
        _counters.inc("drop_bootp_len")
        logging.debug("drop: BOOTP payload too short")
        return None

    # op == 1: BOOTREQUEST (client → server)
    if data[bootp_start] != 1:
        _counters.inc("drop_not_bootrequest")
        logging.debug("drop: BOOTP op=%d (not BOOTREQUEST)", data[bootp_start])
        return None

    # Client hardware address (MAC) is at offset 28 inside BOOTP, 6 bytes.
    mac_start = bootp_start + 28
    mac_bytes = data[mac_start : mac_start + 6]
    mac = ":".join(f"{b:02x}" for b in mac_bytes)

    # Validate magic cookie.
    magic = struct.unpack_from("!I", data, bootp_start + 236)[0]
    if magic != BOOTP_MAGIC_COOKIE:
        _counters.inc("drop_magic_cookie")
        logging.debug("drop: bad BOOTP magic cookie 0x%08x", magic)
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
        _counters.inc("drop_no_opt53")
        logging.debug("drop: DHCP option 53 (message type) not found")
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
    dev_id = sanitize_dev_id(name)  # deduplicated via module-level helper
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
    # Preliminary basicConfig so early errors are visible; will be reconfigured
    # below once options are loaded and the desired log level is known.
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )

    # Load app options written by the Supervisor.
    options_path = "/data/options.json"
    try:
        with open(options_path) as fh:
            options = json.load(fh)
    except FileNotFoundError:
        logging.error("Options file not found: %s", options_path)
        sys.exit(1)

    interface = options.get("interface", "eth0")
    devices = options.get("devices", [])
    log_level_str = options.get("log_level", "info").upper()
    disable_bpf = options.get("disable_bpf", False)

    # Reconfigure logging with the user-chosen level.
    numeric_level = getattr(logging, log_level_str, logging.INFO)
    logging.getLogger().setLevel(numeric_level)
    for handler in logging.getLogger().handlers:
        handler.setLevel(numeric_level)

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
        dev_id = sanitize_dev_id(name)  # sanitized entity ID used in the log
        logging.info("  tracking: %s → %s (sensor.dhcp_last_seen_%s)", mac, name, dev_id)

    if disable_bpf:
        logging.info("BPF filter disabled — running unfiltered capture (disable_bpf=true)")
    logging.debug("log_level=%s disable_bpf=%s", log_level_str, disable_bpf)

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

    if disable_bpf:
        logging.debug("Skipping BPF attachment (disable_bpf=true)")
    else:
        attach_bpf(sock)

    logging.info("Listening on %s …", interface)

    # Start background thread that logs a periodic diagnostic summary at DEBUG level.
    diag_thread = threading.Thread(
        target=_diag_summary_thread,
        args=(stop_event,),
        daemon=True,
        name="diag-summary",
    )
    diag_thread.start()

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
            _counters.inc("drop_msg_type")
            logging.debug("drop: DHCP message type %d not tracked", dhcp_type)
            continue
        if mac not in device_map:
            _counters.inc("drop_mac_not_tracked")
            logging.debug("drop: MAC %s not in tracked device list", mac)
            continue

        _counters.inc("matched")
        name = device_map[mac]
        # Derive the sanitized entity ID the same way update_sensor does.
        dev_id = sanitize_dev_id(name)  # deduplicated via module-level helper
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
