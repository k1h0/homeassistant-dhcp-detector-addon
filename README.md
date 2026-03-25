# DHCP Detector — Home Assistant App

Passive DHCP sniffing for presence detection.  
The add-on monitors DHCP traffic on the host network interface and publishes a
timestamp sensor per tracked device to Home Assistant via **MQTT Discovery** —
entities are registered persistently in the HA Entity Registry and survive HA
restarts without any manual YAML configuration.

> **Requires the [Mosquitto broker](https://github.com/home-assistant/addons/tree/master/mosquitto)
> add-on** (or another MQTT broker) to be installed and running before this
> add-on is started.  The Supervisor will verify this automatically via the
> `services: mqtt:need` declaration and surface a clear error if it is missing.

---

## How it works

1. A raw `AF_PACKET` socket listens for DHCP **DISCOVER**, **REQUEST**, and **INFORM**
   packets sent by devices on the local network.
2. The source MAC address in each packet is matched against your configured device list.
3. On startup, the add-on publishes a retained **MQTT Discovery** config message for
   each tracked device, which registers a persistent `sensor.dhcp_last_seen_<name>`
   entity in HA:
   ```
   Topic:   homeassistant/sensor/dhcp_last_seen_<dev_id>/config
   Retain:  true
   Payload: { "name": "DHCP Last Seen <name>", "device_class": "timestamp", … }
   ```
4. On a MAC match the add-on publishes a retained ISO 8601 timestamp to the
   device's state topic:
   ```
   Topic:   dhcp_presence/<dev_id>/state
   Retain:  true
   Payload: 2026-03-20T14:39:47+01:00
   ```
5. Availability is tracked via a shared topic:
   ```
   Topic:   dhcp_presence/availability
   Retain:  true
   Payload: "online" (on startup) / "offline" (on shutdown or connection loss)
   ```
   HA marks all sensors unavailable automatically when "offline" is received.

The add-on never transmits any DHCP packets and never interferes with your existing
DHCP server.

---

## Installation

1. Install the **Mosquitto broker** add-on from the official HA add-on store and
   start it before proceeding.
2. In Home Assistant, go to **Settings → Add-ons → App store**.
3. Click the **⋮** menu (top-right) and choose **Repositories**.
4. Add the URL of this repository, then click **Add**.
5. Find **DHCP Detector** in the store and click **Install**.
6. Configure the add-on (see [Options](#options) below), then click **Start**.

Alternatively, copy the `dhcp_detector/` directory into your
`/addons/` folder on the Home Assistant OS file system (local add-on install).

---

## Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `interface` | `string` | `eth0` | Network interface to listen on (e.g. `eth0`, `enp3s0`). |
| `devices` | `list` | `[]` | List of `{ mac, name }` pairs to track (see below). |
| `log_level` | `string` | `info` | Logging verbosity: `debug`, `info`, `warning`, or `error`. Use `debug` to enable detailed diagnostics. |
| `disable_bpf` | `bool` | `false` | When `true`, the BPF kernel filter is not attached. Useful when troubleshooting missing packets. |
| `mqtt_host` | `string` | `core-mosquitto` | Hostname or IP address of the MQTT broker. Use the default for the Mosquitto add-on. |
| `mqtt_port` | `integer` | `1883` | TCP port of the MQTT broker. |
| `mqtt_username` | `string` | `""` | MQTT username (leave empty if authentication is not required). |
| `mqtt_password` | `string` | `""` | MQTT password (leave empty if authentication is not required). |

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

Because the add-on only writes a "last seen" timestamp, you derive the presence state
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

* The add-on requires **host networking** (`host_network: true`) and the `NET_RAW`
  Linux capability so it can open a raw socket.  Both are configured automatically.
* The Mosquitto broker add-on (or equivalent) must be running; the Supervisor checks
  this automatically via `services: mqtt:need`.
* Presence latency is typically 1–3 seconds from when a device (re-)joins the network.
* The add-on only ever publishes sensor state — it never reads state from HA and has
  no internal timeout watchdog.

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
add-on logs a one-line counter summary showing the activity during that interval
(counters are reset after each summary, so each line is a delta, not a cumulative total):

```
diag: recv=42 short=0 etype=0 ipv4=0 udp=0 udp_trunc=0 ports=40 bootp=0 bootreq=0 cookie=0 opt53=0 msgtype=0 mac=2 matched=0 ok=0 fail=0
```

Counter meanings:

| Counter | Meaning |
|---------|---------|
| `recv` | Total raw Ethernet frames received in this interval |
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
| `matched` | Packets matched and sensor update attempted |
| `ok` | Successful sensor updates sent via MQTT |
| `fail` | Failed sensor update attempts |

* If `recv=0` after a forced DHCP renewal, **no frames are reaching the add-on at all**.
  This is typically a Proxmox/VM bridge or firewall issue (see below).
* If `recv` is growing but `matched=0`, look at which counter is increasing to
  identify the filtering stage.
* If `etype` is growing, you may have VLAN-tagged frames (802.1Q) on the interface.
* If `ports` or `udp` are growing while `matched=0`, the BPF filter may not be
  working correctly in your environment — the add-on will automatically log a
  **WARNING** after the first 30-second interval suggesting `disable_bpf: true`.

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

If frames are arriving (debug `recv` counter grows) but the `ports` or `udp` counters
are high and `matched=0`, the kernel BPF pre-filter may be ineffective in your
environment.  The add-on detects this automatically: after the first 30-second
diagnostic interval it logs a WARNING if more than half of all received frames were
non-DHCP and no packets matched:

```
WARNING BPF filter may be ineffective: 120 frames received, 118 were non-DHCP
(udp=10 ports=108), yet no packets matched. Try setting disable_bpf: true in add-on options.
```

When you see this warning, set `disable_bpf: true` and restart.  The add-on will then
receive all Ethernet frames without the kernel BPF pre-filter, which resolves the issue
in environments where BPF socket filters are restricted (e.g. some container runtimes or
VMs).  Once the add-on is working you can leave `disable_bpf: true` permanently — the
software filter still rejects non-DHCP frames efficiently.

