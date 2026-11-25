# Radio-ABI fork notes (TahoeRealtekWiFi + RTL radio ABI)

This is a fork of danielnmaldonado/TahoeRealtekWiFi (v0.14.20 line) with a
port of DrogaBox's RTLRadioABI surface so an IO80211 layer kext can drive the
radio (the path toward AirDrop/AWDL). Upstream had zero AWDL support.

## What was added

- `include/rtw/RTLRadioABI.h` — ABI-2 port of DrogaBox's radio ABI (same
  symbol names and layouts, so the same layer kext can adopt either driver).
- `include/rtw/RTLRadioABIGlue.h` + tap in
  `vendor/itl80211/openbsd/net80211/ieee80211_input.c`
  (`ieee80211_enqueue_data`) — data hook diverts delivered Ethernet frames.
- `kext/RTWUSBController.{hpp,cpp}` — `callPlatformFunction` overrides and a
  gate-serialized dispatcher. Implemented ops: Abi, Mac, Status, Channels,
  ScanStart, ScanCopy, Join (WPA2-PSK/open), Leave, DataHook, Tx, Tx80211,
  AwdlHook, SetChannel, AwdlOffch (PM null frames + queue hold), AwdlRate,
  AwdlTxStat. Still Unsupported: AwdlPort (needs a second MACID/ad-hoc port
  in the rtw88 station firmware API), AwdlAgg (host-driven BA agreements).
  Only dual-band backends answer (RTW88 family, 8812AU, 8814AU); the
  adoption check mirrors DrogaBox's `radioBack()`.
- `kext/RTWControl.h` — experimental user-client selectors 6..8:
  `RADIO_STATUS`, `RADIO_TX_80211`, `RADIO_CHANNELS` (additive; old drivers
  reject them, old app versions keep working).
- `Tools/rtwradio.c` — CLI harness: `status | channels | scan | results | tx <hex>`.

Milestone-3 caveats (all documented in code comments):

- `AwdlOffch` always uses 20 MHz for the AWDL slot; the 8814 driver's
  same-block width refinement is not ported. No MACID sleep exists in this
  rtw88 port, so downlink frames keep arriving during slots and are
  discarded (DrogaBox measured this as the ~1.5 MB/s cap before fixing it
  on the 8814).
- `AwdlTxStat`: the 8821C TX-status C2H carries only tag + acked bit, so
  the retry breakdown (retried/retried2) stays 0; `clean`/`lost`/`reports`
  are real.
- `AwdlPort` unsupported: without it, unicast AWDL TX has no hardware ACK
  or retries. The virtual-peer test path does not need it.

All hooks are dormant until a kernel client attaches; without one the driver
behaves exactly like upstream 0.14.20.

## Build

    ./build.command --kext          # -> Release/TahoeRealtekWiFi.kext
    clang -O2 -Wall Tools/rtwradio.c -framework IOKit -framework CoreFoundation \
        -o Tools/rtwradio

## Status / warnings

- Builds clean on Xcode 26.5 SDK, x86_64; no unresolved symbols.
- NOTHING has run against real hardware. First load is bring-up; expect
  panic risk. Back up the EFI before installing.
- The host test suite needs cmake (not installed here) and does not cover
  the new code.
- Remaining for AirDrop: the five Unsupported AWDL ops, an AirLayer build
  for the running macOS (26.5/25F71), Info.plist matching
  `IOProviderClass: RTWUSBController`, and real-device testing.
