#!/usr/bin/env python3
"""
Passive DHCP sniffer for Home Assistant presence detection.

Listens for DHCP DISCOVER, REQUEST, and INFORM packets on a raw socket,
matches source MACs against a configured device list, and publishes
timestamp sensor state to Home Assistant via MQTT Discovery.
"""

import ctypes
import re
import json
import logging
import signal
import socket
import struct
import sys
import threading
import time
from datetime import datetime

# paho-mqtt client for MQTT Discovery and state publishing
import paho.mqtt.client as mqtt_client

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
        "sensor_update_success",
        "sensor_update_fail",
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

    def snapshot_and_reset(self) -> dict:
        """Atomically read and zero all counters; returns the pre-reset values."""
        with self._lock:
            snap = {s: getattr(self, s) for s in self.__slots__[1:]}
            for slot in self.__slots__[1:]:
                setattr(self, slot, 0)
            return snap


_counters = DiagCounters()


def _diag_summary_thread(
    stop_event: threading.Event,
    interval: int = 30,
    disable_bpf: bool = False,
) -> None:
    """Periodically log a one-line diagnostic summary at DEBUG level.

    Counters are reset after each summary so the values reflect the
    activity during that interval (deltas), not cumulative totals.

    When BPF is active (``disable_bpf=False``), a one-time WARNING is
    emitted if many frames are being received but none match DHCP
    client traffic, which suggests the BPF filter is not working as
    expected in the current environment.
    """
    cumulative: dict = {s: 0 for s in DiagCounters.__slots__[1:]}
    bpf_warn_emitted = False

    while not stop_event.wait(interval):
        snap = _counters.snapshot_and_reset()

        # Accumulate lifetime totals for the BPF heuristic (independent of
        # the per-interval reset so the heuristic sees the full picture).
        for key in cumulative:
            cumulative[key] += snap[key]

        logging.debug(
            "diag: recv=%d short=%d etype=%d ipv4=%d udp=%d udp_trunc=%d ports=%d "
            "bootp=%d bootreq=%d cookie=%d opt53=%d msgtype=%d mac=%d "
            "matched=%d ok=%d fail=%d",
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
            snap["sensor_update_success"],
            snap["sensor_update_fail"],
        )

        # BPF effectiveness heuristic — emit a single warning if a
        # meaningful number of frames have arrived but none of them look
        # like DHCP client traffic, implying the BPF pre-filter is letting
        # non-DHCP frames through (or is not filtering at all).
        if not disable_bpf and not bpf_warn_emitted:
            total_recv = cumulative["received"]
            # Count frames that passed the BPF but were not DHCP UDP 68→67.
            # (drop_not_udp: not a UDP packet; drop_ports: wrong UDP ports)
            non_dhcp_udp = cumulative["drop_not_udp"] + cumulative["drop_ports"]
            # Require at least 50 frames before drawing any conclusion and
            # check that the majority are non-DHCP with no matches.
            # Use multiplication to avoid float/integer division imprecision.
            if total_recv >= 50 and non_dhcp_udp * 2 > total_recv and cumulative["matched"] == 0:
                logging.warning(
                    "BPF filter may be ineffective: %d frames received, %d were "
                    "non-DHCP (udp=%d ports=%d), yet no packets matched. "
                    "Try setting disable_bpf: true in add-on options.",
                    total_recv,
                    non_dhcp_udp,
                    cumulative["drop_not_udp"],
                    cumulative["drop_ports"],
                )
                bpf_warn_emitted = True

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

SOL_SOCKET = 1
SO_ATTACH_FILTER = 26
_PCAP_ERRBUF_SIZE = 256
_PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF
_FILTER_EXPR = b"udp and (port 67 or port 68)"


class _BpfInsn(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt",   ctypes.c_uint8),
        ("jf",   ctypes.c_uint8),
        ("k",    ctypes.c_uint32),
    ]


class _BpfProgram(ctypes.Structure):
    _fields_ = [
        ("bf_len",  ctypes.c_uint),
        ("bf_insns", ctypes.POINTER(_BpfInsn)),
    ]


def sanitize_dev_id(name: str) -> str:  # extracted from duplicated inline expressions
    """Convert a friendly device name to a valid HA entity ID segment."""
    return re.sub(r"[^a-z0-9_]", "_", name.lower()).strip("_")


def attach_bpf_libpcap(sock: socket.socket, interface: str) -> bool:
    """Attach a libpcap-compiled BPF filter to *sock* restricting delivery to UDP port 67/68.

    Compiles ``"udp and (port 67 or port 68)"`` at runtime via libpcap so the
    filter is correct for the actual interface DLT (including VLAN-tagged
    environments such as Proxmox vmbr0).  On any failure logs a WARNING and
    returns False without aborting startup.
    """
    # 1. Load libpcap — try candidate names in order.
    lib = None
    for _name in ("libpcap.so.1", "libpcap.so.0.8", "libpcap.so"):
        try:
            lib = ctypes.CDLL(_name)
            break
        except OSError:
            continue
    if lib is None:
        logging.warning(
            "BPF filter could not be attached: "
            "libpcap not found (tried libpcap.so.1, libpcap.so.0.8, libpcap.so)"
        )
        return False

    # 2. Open a pcap handle for the interface.
    lib.pcap_open_live.restype = ctypes.c_void_p
    lib.pcap_open_live.argtypes = [
        ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p,
    ]
    errbuf = ctypes.create_string_buffer(_PCAP_ERRBUF_SIZE)
    handle = lib.pcap_open_live(interface.encode(), 65535, 0, 1000, errbuf)
    if not handle:
        logging.warning(
            "BPF filter could not be attached: pcap_open_live failed: %s",
            errbuf.value.decode(errors="replace"),
        )
        return False

    lib.pcap_close.restype = None
    lib.pcap_close.argtypes = [ctypes.c_void_p]

    try:
        # 3 & 4. Compile the filter expression into a BPF program.
        lib.pcap_compile.restype = ctypes.c_int
        lib.pcap_compile.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_BpfProgram),
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_uint32,
        ]
        fp = _BpfProgram()
        rc = lib.pcap_compile(
            handle,
            ctypes.byref(fp),
            _FILTER_EXPR,
            1,                     # optimize
            _PCAP_NETMASK_UNKNOWN,
        )
        if rc != 0:
            lib.pcap_geterr.restype = ctypes.c_char_p
            lib.pcap_geterr.argtypes = [ctypes.c_void_p]
            err = lib.pcap_geterr(handle)
            logging.warning(
                "BPF filter could not be attached: pcap_compile failed: %s",
                err.decode(errors="replace") if err else "unknown error",
            )
            return False

        lib.pcap_freecode.restype = None
        lib.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgram)]

        try:
            # 5. Apply the compiled program to the raw socket via setsockopt.
            ptr = ctypes.cast(fp.bf_insns, ctypes.c_void_p).value or 0
            if ctypes.sizeof(ctypes.c_void_p) == 8:
                prog_bytes = struct.pack("H6xQ", fp.bf_len, ptr)
            else:
                prog_bytes = struct.pack("H2xI", fp.bf_len, ptr)
            try:
                sock.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, prog_bytes)
            except OSError as exc:
                logging.warning("BPF filter could not be attached: %s", exc)
                return False

            logging.info("BPF filter attached via libpcap — receiving UDP port 67/68 only")
            return True
        finally:
            # 6. Release the compiled BPF program (filter remains on the socket).
            lib.pcap_freecode(ctypes.byref(fp))
    finally:
        # Release the pcap handle (filter remains on the socket).
        lib.pcap_close(handle)


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
        return None
    ethertype = struct.unpack_from("!H", data, 12)[0]
    if ethertype != ETHERTYPE_IPV4:
        _counters.inc("drop_ethertype")
        return None

    # --- IPv4 header ---
    ip_start = 14
    if len(data) < ip_start + 20:
        _counters.inc("drop_not_ipv4")
        return None
    ip_ihl = (data[ip_start] & 0x0F) * 4
    ip_proto = data[ip_start + 9]
    if ip_proto != IP_PROTO_UDP:
        _counters.inc("drop_not_udp")
        return None

    # --- UDP header (8 bytes) ---
    udp_start = ip_start + ip_ihl
    if len(data) < udp_start + 8:
        _counters.inc("drop_udp_truncated")
        return None
    src_port = struct.unpack_from("!H", data, udp_start)[0]
    dst_port = struct.unpack_from("!H", data, udp_start + 2)[0]
    if src_port != DHCP_CLIENT_PORT or dst_port != DHCP_SERVER_PORT:
        _counters.inc("drop_ports")
        return None

    # --- BOOTP / DHCP payload ---
    # Fixed BOOTP header: 236 bytes; magic cookie: 4 bytes → 240 bytes minimum.
    bootp_start = udp_start + 8
    if len(data) < bootp_start + 240:
        _counters.inc("drop_bootp_len")
        return None

    # op == 1: BOOTREQUEST (client → server)
    if data[bootp_start] != 1:
        _counters.inc("drop_not_bootrequest")
        return None

    # Client hardware address (MAC) is at offset 28 inside BOOTP, 6 bytes.
    mac_start = bootp_start + 28
    mac_bytes = data[mac_start : mac_start + 6]
    mac = ":".join(f"{b:02x}" for b in mac_bytes)

    # Validate magic cookie.
    magic = struct.unpack_from("!I", data, bootp_start + 236)[0]
    if magic != BOOTP_MAGIC_COOKIE:
        _counters.inc("drop_magic_cookie")
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
        return None

    return mac, dhcp_type


# ---------------------------------------------------------------------------
# MQTT helpers
# ---------------------------------------------------------------------------

# Shared availability topic for all sensors managed by this add-on.
AVAILABILITY_TOPIC = "dhcp_presence/availability"


def mqtt_connect(host: str, port: int, username: str, password: str) -> mqtt_client.Client:
    """Create and connect a paho MQTT client.

    Returns the connected client instance.
    """
    client = mqtt_client.Client()
    # Set last-will so the broker publishes "offline" if the connection drops unexpectedly.
    client.will_set(AVAILABILITY_TOPIC, payload="offline", retain=True)
    if username:
        client.username_pw_set(username, password or None)
    client.connect(host, port, keepalive=60)
    client.loop_start()
    logging.info("Connected to MQTT broker at %s:%d", host, port)
    return client


def publish_discovery(client: mqtt_client.Client, device_map: dict) -> None:
    """Publish retained MQTT Discovery config messages for each tracked device.

    Registers a persistent timestamp sensor in HA for every entry in device_map.
    Called once on startup before the availability "online" message is sent.
    """
    for _mac, name in device_map.items():
        dev_id = sanitize_dev_id(name)
        topic = f"homeassistant/sensor/dhcp_last_seen_{dev_id}/config"
        payload = json.dumps({
            "name": f"DHCP Last Seen {name}",
            "state_topic": f"dhcp_presence/{dev_id}/state",
            "device_class": "timestamp",
            "unique_id": f"dhcp_last_seen_{dev_id}",
            "availability_topic": AVAILABILITY_TOPIC,
            "payload_available": "online",
            "payload_not_available": "offline",
        })
        client.publish(topic, payload=payload, retain=True)
        logging.info("Published discovery config for sensor.dhcp_last_seen_%s", dev_id)


def publish_availability(client: mqtt_client.Client, available: bool) -> None:
    """Publish the add-on availability (online/offline) with retain=True.

    Called after discovery on startup ("online") and on shutdown ("offline").
    """
    payload = "online" if available else "offline"
    client.publish(AVAILABILITY_TOPIC, payload=payload, retain=True)
    logging.info("Published availability: %s", payload)


def publish_state(client: mqtt_client.Client, mac: str, name: str) -> bool:
    """Publish a retained ISO 8601 timestamp to the device's state topic.

    Replaces the former update_sensor() REST API call.
    Returns True on success, False on error.
    """
    dev_id = sanitize_dev_id(name)  # deduplicated via module-level helper
    timestamp = datetime.now().astimezone().isoformat()
    topic = f"dhcp_presence/{dev_id}/state"
    try:
        result = client.publish(topic, payload=timestamp, retain=True)
        result.wait_for_publish(timeout=5)
        return True
    except (ValueError, RuntimeError) as exc:
        logging.error("MQTT publish error for %s (%s): %s", name, mac, exc)
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
    # MQTT broker connection settings from add-on options
    mqtt_host = options.get("mqtt_host", "core-mosquitto")
    mqtt_port = options.get("mqtt_port", 1883)
    mqtt_username = options.get("mqtt_username", "")
    mqtt_password = options.get("mqtt_password", "")

    # Reconfigure logging with the user-chosen level.
    numeric_level = getattr(logging, log_level_str, logging.INFO)
    logging.getLogger().setLevel(numeric_level)
    for handler in logging.getLogger().handlers:
        handler.setLevel(numeric_level)

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

    # Connect to MQTT broker and publish discovery configs + "online" availability.
    try:
        mqttc = mqtt_connect(mqtt_host, mqtt_port, mqtt_username, mqtt_password)
    except Exception as exc:
        logging.error("Failed to connect to MQTT broker at %s:%d: %s", mqtt_host, mqtt_port, exc)
        sys.exit(1)

    # Publish retained discovery config for each tracked device once on startup.
    publish_discovery(mqttc, device_map)
    # Signal that the add-on is online; HA marks all sensors available via availability_topic.
    publish_availability(mqttc, available=True)

    stop_event = threading.Event()

    def handle_shutdown_signal(signum, frame):
        logging.info("Received signal %s — shutting down.", signum)
        # Publish "offline" so HA marks all sensors unavailable via availability_topic.
        publish_availability(mqttc, available=False)
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
        attach_bpf_libpcap(sock, interface)

    logging.info("Listening on %s …", interface)

    # Start background thread that logs a periodic diagnostic summary at DEBUG level.
    diag_thread = threading.Thread(
        target=_diag_summary_thread,
        args=(stop_event,),
        kwargs={"disable_bpf": disable_bpf},
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
            continue
        if mac not in device_map:
            _counters.inc("drop_mac_not_tracked")
            continue

        _counters.inc("matched")
        name = device_map[mac]
        # Derive the sanitized entity ID the same way publish_state does.
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

        ok = publish_state(mqttc, mac, name)
        if ok:
            _counters.inc("sensor_update_success")
        else:
            _counters.inc("sensor_update_fail")

    sock.close()
    mqttc.loop_stop()
    mqttc.disconnect()
    logging.info("DHCP Detector stopped.")


if __name__ == "__main__":
    main()
