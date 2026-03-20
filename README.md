# DHCP Detector — Home Assistant Add-on

Passive DHCP sniffing for presence detection.  
The add-on monitors DHCP traffic on the host network interface and writes a
timestamp sensor per tracked device to Home Assistant via the Supervisor REST API —
no MQTT, no extra integrations, no manual YAML required.

---

## How it works

1. A raw `AF_PACKET` socket listens for DHCP **DISCOVER**, **REQUEST**, and **INFORM**
   packets sent by devices on the local network.
2. The source MAC address in each packet is matched against your configured device list.
3. On a match the add-on calls the Supervisor REST API to create or update a
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

The add-on never transmits any DHCP packets and never interferes with your existing
DHCP server.

---

## Installation

1. In Home Assistant, go to **Settings → Add-ons → Add-on store**.
2. Click the **⋮** menu (top-right) and choose **Repositories**.
3. Add the URL of this repository, then click **Add**.
4. Find **DHCP Detector** in the store and click **Install**.
5. Configure the add-on (see [Options](#options) below), then click **Start**.

Alternatively, copy the `dhcp_detector/` directory into your
`/addons/` folder on the Home Assistant OS file system (local add-on install).

---

## Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `interface` | `string` | `eth0` | Network interface to listen on (e.g. `eth0`, `enp3s0`). |
| `devices` | `list` | `[]` | List of `{ mac, name }` pairs to track (see below). |

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
* The `SUPERVISOR_TOKEN` environment variable is injected automatically by the
  Supervisor — no credentials need to be entered.
* Presence latency is typically 1–3 seconds from when a device (re-)joins the network.
* The add-on only ever writes sensor state — it never reads state from HA and has no
  internal timeout watchdog.
