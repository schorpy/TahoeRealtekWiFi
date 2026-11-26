# AirLayer (RTL88AirLayer.kext) for TahoeRealtekWiFi

This folder holds the native IO80211 layer that lets macOS use the USB radio as
if it were an Apple Wi-Fi card: the normal Wi-Fi menu on `en1`, and `awdl0`
for AirDrop. The layer does not touch hardware. It drives the radio through
the radio ABI (`rtlRadio*` calls via `callPlatformFunction`), defined in
`../include/rtw/RTLRadioABI.h` and implemented by this repo's
TahoeRealtekWiFi driver.

## Origin and license

The layer is the work of DrogaBox, from
[DrogaBox/RTL8814Native](https://github.com/DrogaBox/RTL8814Native)
(`Source/AirLayer`, `Source/IO80211`, the radio ABI header and the gate
tool), at upstream commit `86b00f7` (2026-11-24). It is licensed under the
GPL-2.0; see `LICENSE` in this folder.

Changes made here:

- Renamed from `RTL8814AirLayer.kext` to `RTL88AirLayer.kext` (bundle ID
  `io.github.schorpy.RTL88AirLayer`), since this build drives the rtw88 chips
  through TahoeRealtekWiFi. Class names and boot-args are unchanged.

- `Source/AirLayer/Info-Tahoe.plist`: personality that attaches the layer to
  TahoeRealtekWiFi (`IOProviderClass RTWUSBController`). It is the default.
- Fixes in `RTLAirLayer.cpp` and `VersionGate.h` (WPA2 passphrase to PMK,
  SAE handling, MAC address, OS version gate).
- `rtlawdl_mccx` boot-arg: lets a 2.4 GHz network serve AWDL on channel 149
  (opt-in; band switching is expensive).

## Build

```sh
cd airlayer
./build_airlayer.sh          # -> Build/RTL88AirLayer.kext
```

The layer is built against the IO80211 class layout of macOS 26.x
(`Source/IO80211/IO80211_25_6_0.h`). At boot a version gate checks the running
build against `Tools/airlayer_builds.txt`; an unlisted build stays inert unless
the boot-arg `rtlairtrust=<build>` names it.

## Boot-args

| Boot-arg | Effect |
|---|---|
| `rtlair=2` | layer active: native Wi-Fi (scan, join, data) |
| `rtlawdl=1` | creates `awdl0` |
| `rtlawdl_tx=1` | AWDL transmit (needed for AirDrop) |
| `rtlawdl_mcc=1` | serve AWDL slots while associated off the social channels |
| `rtlawdl_ratemax=N` | cap the AWDL data rate (index into 6/12/24/36/48/54/65 Mb/s) |
| `rtlairtrust=<build>` | start on a macOS build not yet in the validated list |

## Status

Tested on macOS 26.7.3 (25G342) with an RTL8821CU dongle: native Wi-Fi works;
iPhone-to-Mac AirDrop works at close range with the Mac on a 5 GHz network,
and is not yet reliable at a distance.
