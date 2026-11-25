# Tahoe Wi-Fi USB — native macOS Wi-Fi and AirDrop

> **Experimental.** This fork makes a Realtek USB Wi-Fi adapter appear to macOS
> as a built-in Wi-Fi card: the normal Wi-Fi menu, and AirDrop over AWDL.
> AirDrop works, but only at short range so far. See [Status](#status).

This fork adds two things to the original
[Tahoe Wi-Fi USB driver](https://github.com/danielnmaldonado/TahoeRealtekWiFi):

1. **A radio interface ("radio ABI")** in the driver: about 20
   `rtlRadio*` calls (scan, join, send, receive, AWDL channel slots, AWDL
   port, delivery reports) that another kext can use to drive the radio.
2. **The AirLayer** (`airlayer/`, `RTL8814AirLayer.kext`) by
   [DrogaBox](https://github.com/DrogaBox/RTL8814Native). It implements the
   classes macOS expects from an Apple Wi-Fi card on top of that interface.

```
 macOS Wi-Fi menu · AirDrop · airportd · sharingd     (Apple, unchanged)
 IO80211Family: Apple's Wi-Fi and AWDL logic          (Apple, unchanged)
        │
 RTL8814AirLayer.kext   en1 = native Wi-Fi, awdl0 = AWDL / AirDrop
        │  rtlRadio* calls
 TahoeRealtekWiFi.kext  USB radio driver (rtw88 based)
        │  USB
 Realtek USB adapter
```

With both kexts loaded you get:

- **Native Wi-Fi.** The adapter shows up as `Wi-Fi` in System Settings and the
  menu bar. You scan, join (WPA2 / WPA3-transition networks with a WPA2 PSK)
  and use the network like on a real Mac. No menu-bar app is needed.
- **AirDrop.** `awdl0` comes up, AWDL syncs with nearby Apple devices, and
  iPhone ↔ Mac AirDrop works at close range.

## Status

Tested on **macOS Tahoe 26.7.3 (25G342)**, Intel, OpenCore, with an
**RTL8821CU** Wi-Fi + Bluetooth combo adapter (`0bda:c820`).

| Feature | State |
| --- | --- |
| Native Wi-Fi (scan, join, DHCP, data) | ✅ works, stable |
| AWDL sync with Apple devices | ✅ works |
| AirDrop iPhone → Mac (incl. file transfer) | ✅ works at ~10–50 cm |
| AirDrop Mac → iPhone (Finder) | ⚠️ works, not always |
| AirDrop at 1 m or more | ❌ not reliable yet |
| A-MPDU for AWDL data (`rtlRadioAwdlAgg`) | ❌ not implemented (single frames) |
| Other chipsets | ❓ untested (the radio ABI accepts the dual-band RTW88, RTL8812AU and RTL8814AU families) |

**Use a 5 GHz network for the Mac's Wi-Fi.** AirDrop traffic runs on 5 GHz
channel 149. On a 5 GHz network the radio does not have to switch bands, and
macOS only fully trusts AirDrop peers it hears on 5 GHz. A network on channel
149 is ideal. On 2.4 GHz, AirDrop needs `rtlawdl_mccx=1` (band switching),
which can drop the Wi-Fi link.

**Range is limited** by the adapter's radio (weak signal from a rear USB port)
and by AWDL running in software over USB instead of in Wi-Fi firmware. A USB
extension cable that puts the adapter in the open helps.

## Requirements

- Intel Mac or Hackintosh with **OpenCore**, macOS **26.x (Tahoe)**. The
  AirLayer is built against the macOS 26 IO80211 class layout.
- A supported Realtek USB adapter (see below; RTL8821CU tested).
- For Bluetooth on a combo adapter, and for AirDrop: **BlueToolFixup** and a
  firmware loader for the Bluetooth chip (for example
  RealtekBluetoothFirmware). Broadcom kexts (BrcmPatchRAM3,
  BrcmFirmwareRepo) are **not** needed for Realtek hardware.
- **Do not** load IO80211FamilyLegacy / IOSkywalkFamily / AirPortBrcmNIC.
  The AirLayer uses macOS's own Wi-Fi stack.

## Build

```sh
./build.command --kext          # -> Release/TahoeRealtekWiFi.kext
cd airlayer && ./build_airlayer.sh   # -> airlayer/Build/RTL8814AirLayer.kext
```

## Install (OpenCore)

1. Copy both kexts to `EFI/OC/Kexts/`.
2. In `config.plist` → `Kernel` → `Add`, add `TahoeRealtekWiFi.kext` and,
   **after it**, `RTL8814AirLayer.kext`.
3. Add boot-args (`NVRAM` → `Add` → `7C436110-AB2A-4BBB-A880-FE41995C9F82` →
   `boot-args`):

   ```
   rtlair=2 rtlawdl=1 rtlawdl_tx=1 rtlawdl_mcc=1 rtlairtrust=<your build>
   ```

   `<your build>` is the output of `sw_vers -buildVersion`, for example
   `25G342`. A build missing from `airlayer/Tools/airlayer_builds.txt` only
   starts with `rtlairtrust`. That's a safety gate, since the layer depends on
   the exact macOS class layout.
4. Reboot, open the Wi-Fi menu, and join a 5 GHz network.
5. For AirDrop: Finder → AirDrop → "Allow me to be discovered by: Everyone".

Keep a second, known-good EFI to fall back to while testing.

### Boot-args

| Boot-arg | Effect |
| --- | --- |
| `rtlair=2` | AirLayer active: native Wi-Fi (`rtlair=1` = scan only) |
| `rtlawdl=1` | create `awdl0` |
| `rtlawdl_tx=1` | AWDL transmit (needed for AirDrop) |
| `rtlawdl_mcc=1` | serve AWDL slots while associated to a network off the AWDL channels |
| `rtlawdl_mccx=1` | also serve 5 GHz AWDL from a 2.4 GHz network (band switching; can drop Wi-Fi) |
| `rtlawdl_ratemax=N` | cap the AWDL data rate (index into 6/12/24/36/48/54/65 Mb/s) |
| `rtlairtrust=<build>` | start the layer on a macOS build not yet listed as validated |

More AirLayer details: [airlayer/README.md](airlayer/README.md).

## What changed in the driver

- Radio ABI (`include/rtw/RTLRadioABI.h`, shared with the AirLayer): scan,
  join (WPA2 PSK), data hook, raw 802.11 TX, AWDL RX hook, channel parking,
  AWDL off-channel slots, AWDL rate and TX status.
- AWDL port 1 (hardware ACK for unicast to `awdl0`), with `RCR_AAP` while
  active, as on DrogaBox's RTL8814AU setup.
- AWDL frames are sent and labelled with the channel the radio is really on
  during an AWDL slot.
- A failed channel switch is recovered instead of disabling the radio.
- TX delivery reports reach the AirLayer, and unicast AWDL data may fall back
  to slower rates on retries.
- Native-Wi-Fi fixes: private MAC address no longer breaks the chip identity
  check; scans while associated no longer drop the link.

## Credits

- **MaLd0n**: the Tahoe Wi-Fi USB driver and app this fork is based on.
- **DrogaBox**: the AirLayer, the radio ABI design and the reverse engineering
  of the macOS AWDL stack
  ([RTL8814Native](https://github.com/DrogaBox/RTL8814Native)).
- The Linux **rtw88** and OpenBSD **net80211** projects the driver builds on.

## License

GPL-2.0, see [LICENSE-GPL-2.0.txt](LICENSE-GPL-2.0.txt). The AirLayer keeps
its own license file in [airlayer/LICENSE](airlayer/LICENSE).

---

## Base driver: Tahoe Wi-Fi USB

The original driver also works on its own, without the AirLayer, with its
menu-bar app. Realtek USB Wi-Fi driver and menu-bar app for **Intel Macs**
running **macOS Ventura 13, Sonoma 14, Sequoia 15 and Tahoe 26**: scan for
networks, connect using WPA2-Personal, switch between USB adapters and check
signal strength from the macOS menu bar. Developed and adapted for macOS by
**MaLd0n**.

### Supported chipsets

| Bands | Chipsets |
| --- | --- |
| 2.4 GHz | RTL8188EU, RTL8192CU, RTL8192EU, RTL8192FU, RTL8710BU, RTL8723BU |
| 2.4 / 5 GHz | RTL8192DU, RTL8812AU, RTL8814AU, RTL8821AU, RTL8821CU, RTL8822BU, RTL8822CU |

### Supported adapter examples

| Adapter | Chipset | USB ID |
| --- | --- | --- |
| TP-Link Archer T9UH | RTL8814AU | `2357:0106` |
| TP-Link TL-WN822N v4 | RTL8192EU | `2357:0108` |
| TP-Link TL-WN823N v2 | RTL8192EU | `2357:0109` |
| ASUS USB-AC56 | RTL8812AU | `0b05:17d2` |
| ASUS USB-AC68 | RTL8814AU | `0b05:1817` |
| NETGEAR A7000 | RTL8814AU | `0846:9054` |
| Edimax EW-7822UAC | RTL8812AU | `7392:a822` |

Support, bands and wireless modes depend on the exact USB ID and hardware
revision. See the [complete adapter list](docs/USB-WIFI-SUPPORT.txt) for all
models and chipset-specific capabilities. Only the RTL8821CU has been tested
with the AirLayer.
