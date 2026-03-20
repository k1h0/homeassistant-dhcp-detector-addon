# DHCP Detector — Home Assistant App

Passive DHCP sniffing for presence detection.  
The app monitors DHCP traffic on the host network interface and writes a
timestamp sensor per tracked device to Home Assistant via the Supervisor REST API —
no MQTT, no extra integrations, no manual YAML required.

---

## How it works

1. A raw `AF_PACKET` socket listens for DHCP **DISCOVER**, **REQUEST**, and **INFORM**
   packets sent by devices on the local network.
2. The source MAC address in each packet is matched against your configured device list.
3. On a match the app calls the Supervisor REST API to create or update a
   `sensor.dhcp_last_seen_<name>` entity:
   ```
   POST http://supervisor/homeassistant/api/states/sensor.dhcp_last_seen_<name>
   {
     "state": "2026-03-20T14:39:47+01:00",
     "attributes": {
       "device_class": "timestamp",
       "friendly_name": "DHCP Last Seen <name>",
       "mac": "aa:bb:cc:dd:ee:ff"
     }
   }
   ```
   HA creates the sensor entity automatically on the first call; subsequent calls
   update the timestamp.

The app never transmits any DHCP packets and never interferes with your existing
DHCP server.

---

## Installation

1. In Home Assistant, go to **Settings → Add-ons → App store**.
2. Click the **⋮** menu (top-right) and choose **Repositories**.
3. Add the URL of this repository, then click **Add**.
4. Find **DHCP Detector** in the store and click **Install**.
5. Configure the app (see [Options](#options) below), then click **Start**.

Alternatively, copy the `dhcp_detector/` directory into your
`/addons/` folder on the Home Assistant OS file system (local app install).

---

## Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `interface` | `string` | `eth0` | Network interface to listen on (e.g. `eth0`, `enp3s0`). |
| `devices` | `list` | `[]` | List of `{ mac, name }` pairs to track (see below). |
| `log_level` | `string` | `info` | Logging verbosity: `debug`, `info`, `warning`, or `error`. Use `debug` to enable detailed diagnostics. |
| `disable_bpf` | `bool` | `false` | When `true`, the BPF kernel filter is not attached. Useful when troubleshooting missing packets. |

### Devices list example

```yaml
devices:
  - mac: "aa:bb:cc:dd:ee:ff"
    name: "alice_phone"
  - mac: "11:22:33:44:55:66"
    name: "bob_laptop"
```

* `mac` — the device's MAC address (colon- or hyphen-separated, case-insensitive).  
  For iOS devices that use **Private Wi-Fi Address**, use the per-network stable MAC
  shown in the Wi-Fi details for your home network.
* `name` — used to form the sensor entity ID in Home Assistant:
  `sensor.dhcp_last_seen_<name>`.

---

## Sensor naming

Each tracked device gets one sensor entity:

| `name` in config | Entity ID in HA |
|------------------|----------------|
| `alice_phone` | `sensor.dhcp_last_seen_alice_phone` |
| `bob_laptop` | `sensor.dhcp_last_seen_bob_laptop` |

The sensor state is an ISO 8601 timestamp (with local timezone offset) of the last
DHCP packet seen from that device.  Home Assistant recognises it as a `timestamp`
device class, so it appears as a formatted date/time in the UI.

---

## Deriving home / not_home state

Because the app only writes a "last seen" timestamp, you derive the presence state
in Home Assistant using a **Template Binary Sensor**.  Add the following to your
`configuration.yaml` (or a package file):

```yaml
template:
  - binary_sensor:
      - name: "Alice's iPhone present"
        device_class: presence
        state: >
          {{ (now() - (states('sensor.dhcp_last_seen_alice_phone') | as_datetime))
             < timedelta(minutes=10) }}
      - name: "Bob's Laptop present"
        device_class: presence
        state: >
          {{ (now() - (states('sensor.dhcp_last_seen_bob_laptop') | as_datetime))
             < timedelta(minutes=10) }}
```

Adjust `timedelta(minutes=10)` to suit your network's DHCP renewal interval.

---

## Notes

* The app requires **host networking** (`host_network: true`) and the `NET_RAW`
  Linux capability so it can open a raw socket.  Both are configured automatically.
* The `SUPERVISOR_TOKEN` environment variable is injected automatically by the
  Supervisor — no credentials need to be entered.
* Presence latency is typically 1–3 seconds from when a device (re-)joins the network.
* The app only ever writes sensor state — it never reads state from HA and has no
  internal timeout watchdog.

---

## Troubleshooting

### No sensor is created / add-on is silent

The sensor `sensor.dhcp_last_seen_<name>` is only created the **first time** the
add-on receives a DHCP DISCOVER, REQUEST, or INFORM packet from a tracked device.
If no sensor appears, the add-on is not receiving matching packets.

**Step 1 — Force a DHCP renewal on the client device**

Toggle the device's Wi-Fi off and on (or use "Forget this network" and reconnect).
Watch the add-on log for a line like:

```
2026-03-20 14:39:47  DHCP REQUEST   alice_phone (aa:bb:cc:dd:ee:ff) → sensor.dhcp_last_seen_alice_phone
```

If that line never appears, the packets are not reaching the add-on.

**Step 2 — Enable debug logging**

Set `log_level: debug` in the add-on options and restart.  Every 30 seconds the
add-on logs a one-line counter summary:

```
diag: recv=42 short=0 etype=0 ipv4=0 udp=0 ports=40 bootp=0 bootreq=0 cookie=0 opt53=0 msgtype=0 mac=2 matched=0
```

Counter meanings:

| Counter | Meaning |
|---------|---------|
| `recv` | Total raw Ethernet frames received |
| `short` | Frame too short to contain an Ethernet header |
| `etype` | EtherType not IPv4 (0x0800) — e.g. ARP, IPv6, VLAN-tagged |
| `ipv4` | IPv4 header truncated |
| `udp` | IP protocol not UDP |
| `udp_trunc` | UDP header truncated |
| `ports` | UDP ports not 68→67 (not a DHCP client packet) |
| `bootp` | BOOTP payload too short |
| `bootreq` | BOOTP op not BOOTREQUEST |
| `cookie` | Invalid BOOTP magic cookie |
| `opt53` | DHCP option 53 (message type) missing |
| `msgtype` | DHCP message type not DISCOVER/REQUEST/INFORM |
| `mac` | Valid DHCP packet but MAC not in tracked device list |
| `matched` | Packets matched and sensor updated |

* If `recv=0` after a forced DHCP renewal, **no frames are reaching the add-on at all**.
  This is typically a Proxmox/VM bridge or firewall issue (see below).
* If `recv` is growing but `matched=0`, look at which counter is increasing to
  identify the filtering stage.
* If `etype` is growing, you may have VLAN-tagged frames (802.1Q) on the interface.

**Step 3 — Check Proxmox bridge/firewall (VM setups)**

In a VM on Proxmox, broadcast DHCP frames may not be forwarded to the VM's virtual
NIC if the bridge is not in promiscuous mode or if the Proxmox firewall is active.

Check that frames reach the VM's TAP interface on the Proxmox host:

```sh
tcpdump -eni tap100i0 udp port 67 or 68   # replace 100 with your VM ID
```

If packets appear on `vmbr0` but not on `tap100i0`, enable promiscuous mode:

```sh
ip link set dev vmbr0 promisc on
```

Also verify that the Proxmox Datacenter/Node/VM firewall is not filtering broadcast
traffic (`pve-firewall status`).

**Step 4 — Try disabling the BPF filter**

If frames are arriving (debug `recv` counter grows) but are still not matched, try
setting `disable_bpf: true` and restarting.  The add-on will then receive all
Ethernet frames without the kernel BPF pre-filter, which can help rule out a
BPF-related issue.  Remember to set it back to `false` once diagnostics are complete.

