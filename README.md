# Time Capsule ReLive

*When Apple leaves, Time Capsule relives.* A second life for the Apple AirPort Time Capsule (802.11ac, 5th generation, A1470) — without opening it.*
🇫🇷 [Version française](README.fr.md)

Apple stopped updating the AirPort Time Capsule in 2019, and macOS 27 removed the protocols it relies on (AFP,
SMB 1). The hardware is still good: a dual-band 802.11ac access point, gigabit ports and a 2–3 TB disk. This
project keeps it useful, **reversibly**, by adding tools next to Apple's firmware instead of replacing it.

It builds on [TimeCapsuleSMB](https://github.com/jamesyc/TimeCapsuleSMB), which brings SSH and a modern Samba
(SMB 3) to the device. Everything here is complementary.

## What you get

| Area | Status | What |
|---|---|---|
| **SMB 3 file sharing / Time Machine** | ✅ via TimeCapsuleSMB | works with macOS 27 and Linux; measured 20–28 MB/s |
| **Configure Wi-Fi without AirPort Utility** | ✅ tested | `outils/tc-wifi.py`: read/write the whole Wi-Fi config (ACP property `WiFi`), exact backup and byte-for-byte restore |
| **ACP protocol documentation** | ✅ | table of the **533** ACP properties of firmware 7.9.1 (previously 78 known), the CFB0 format, Wi-Fi keys (`raSt`, `raWM`, `dWDS`…) |
| **Wi-Fi client and repeater with any router** | ✅ tested | one radio joins a box, a router or a phone hotspot (WPA2); the Time Capsule becomes reachable on it and **shares the connection** on its own Wi-Fi and on its Ethernet port (address translation, ~110–125 Mbit/s measured). Works around Apple's two blocks: no IP address on a client radio, repeater mode limited to Apple base stations. See [docs/spec-nat.md](docs/spec-nat.md) (French) |
| **Automatic mode** | ✅ tested | cable to a box: both radios broadcast the Time Capsule's Wi-Fi; cable unplugged, or to a router plugged in by its WAN port: it joins the best-received known network and shares the connection; switches back when the cable returns |
| **Trusted networks** | ✅ | SSH, ReLive, file sharing and Bonjour are only relayed on networks marked as trusted (nothing exposed on a hotel or public Wi-Fi) |
| **Run Go programs on the device** | ✅ | patched Go runtime for Apple's NetBSD 6 (threads, `_lwp_park`): goroutines, GC, preemption, network all work |
| **WireGuard server** | ✅ tested | `wg-tc`: userspace WireGuard (wireguard-go + gVisor netstack), no kernel `tun` needed, ~5 MB RAM, ~10 Mbit/s |
| **More memory** | ✅ | `tc-swap`: 256 MB swap file on the disk (the device has 256 MB RAM); disable unused Apple daemons |
| **Web admin (ReLive)** | ✅ tested | dashboard (disk, SMART, temperatures, memory, services, backups), Wi-Fi settings with automatic backup/restore, join a network, automatic mode, logs, reboot — runs on the device, over HTTPS, ~9 MB RAM |
| **Tailscale** | 🧪 | builds (userspace networking); to be retested from RAM (programs must not run from the HFS+ disk, see [docs/go-netbsd6.md](docs/go-netbsd6.md)) |
| **Monitoring** | ✅ | probe for a home server: disk, temperatures, fan, Samba, backup age → ntfy alerts |
| **Encrypted off-server backups** | ✅ example | restic (encrypted on the server) to the Time Capsule over SMB, nightly, with retention |
| **Read the old disk from macOS 27** | ✅ | read-only SMB 1 client + parallel resumable copy of Time Machine bundles |
| **Firmware analysis** | ✅ | download/decrypt Apple's 7.9.1 image, extract its FFS root filesystem, Ghidra scripts |

Not pursued (see [the study](docs/etude-possibilites.md)): OpenWrt — the BCM4360 Wi-Fi chips have no usable free
driver, so you would lose Wi-Fi, and flashing needs opening the device.

## Safety first

- **Reversible**: every write saves the previous state first and has a restore command. Nothing is flashed.
- **No Apple code is distributed**: only our tools, notes and patches. Firmware analysis downloads Apple's own
  update from Apple's servers on your machine.
- ACP (Apple's admin protocol) protects the password poorly: use these tools on your **local network only**.
- Security review before publication: [docs/revue-securite.md](docs/revue-securite.md) (French).
- Back up your Time Machine data before changing anything (`outils/tc-smb1.py` can copy it, even from macOS 27).

## Quick start

```sh
# 1. SMB 3 + SSH: follow TimeCapsuleSMB's README (tcapsule configure / deploy / doctor)
# 2. This project
python3 -m venv .re-tools/venv && .re-tools/venv/bin/pip install pycryptodome impacket passlib
echo "TC_HOTE=192.168.1.20" > config.local           # your Time Capsule's IP
.re-tools/venv/bin/python outils/acp-lire.py          # read-only dump of all settings (asks the password)
.re-tools/venv/bin/python outils/tc-wifi.py voir      # current Wi-Fi configuration
./outils/construire-tc.sh                             # build the device tools (patched Go) into binaires/
```

The device tools (ReLive, tc-pont, tc-dhcp, relais.sh) start at boot through TimeCapsuleSMB's `/mnt/Flash/rc.user`
hook, which runs `outils/tc/seconde-vie.sh` then `outils/tc/demarrage.sh`: nothing is written to the firmware.

## What we learned along the way

- **A real router makes a better repeater.** A recent Wi-Fi 6 router in repeater mode, with the Time Capsule wired
  behind it, gives 3 to 4 times the Time Capsule's own throughput (360–450 vs 110–125 Mbit/s measured). The Time
  Capsule's repeater stays useful when it is all you have.
- **Without a cable, the Time Capsule tops out at 25–60 Mbit/s** to a Wi-Fi device: its 2.4 GHz radio is limited to
  20 MHz (the chip's only European country table does not allow 40 MHz), and a radio shared between receiving and
  broadcasting loses a lot. Measurements: [docs/spec-nat.md](docs/spec-nat.md) (French).

Documentation (French): [firmware analysis & ACP](docs/analyse-firmware-7.9.1.md) ·
[WireGuard & memory](docs/wireguard.md) · [SMB 3 tests](docs/tests-smb3.md) ·
[encrypted backups](docs/sauvegarde-immich.md) · [extra services](docs/objectif-5-services.md) ·
[what else is possible](docs/etude-possibilites.md) · [state of the art](docs/ETAT-DE-L-ART.md)

## Credits

[TimeCapsuleSMB](https://github.com/jamesyc/TimeCapsuleSMB) (SSH, Samba, ACP client, firmware keys) ·
[airpyrt-tools](https://github.com/x56/airpyrt-tools) (first ACP work) ·
[wireguard-go](https://git.zx2c4.com/wireguard-go) · [gVisor](https://gvisor.dev) ·
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) · [REA](https://github.com/morluto/rea)

## License

GPL-3.0 (see [LICENSE](LICENSE)). Code adapted from wireguard-go keeps its MIT notice.
