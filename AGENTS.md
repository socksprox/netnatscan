# AGENTS.md - netnatscan

Flutter macOS + Windows app: LAN device scanner in the style of iOS
"NetAnalyzer".

**Not targeting the App Store** — private APIs, disabling the sandbox,
and subprocesses are all fair game. **Policy: the public API is always
the baseline; private APIs are optional enrichment layered on top.**
Guard every private call (`responds(to:)` / nil checks) and always emit
the public value too, so the app works fully even if every private call
returns nil — selectors can and will vanish across macOS versions.
Inventory: `docs/private-apis.md`.

## Design

- UI rules: `.devin/rules/ui-design.md` — TDesign-styled components copied from
  `/Users/tamino/Code/N3DS/SFYGameTransferrer`. **No `tdesign_flutter` package**;
  `lib/widgets/tdesign.dart` locally re-implements `TDText`/`TDTheme`/`TDToast`.
- Reference implementation for scanning logic (non-UI):
  `/Users/tamino/Downloads/netscli-main` (Rust).

## Architecture

`lib/screens/main_navigation_screen.dart` hosts an `IndexedStack` of
tabs (`ScanScreen`, `WifiNetworksScreen`, `ConnectionInfoScreen`,
`ToolsScreen`) so tab state survives switches. `lib/widgets/app_navigation.dart` is the
responsive nav — vertical sidebar ≥ ~1024px wide, `BottomNavigationBar`
below. Tabs have **no app bar** — each screen has a top-right row
(theme toggle in narrow layout + refresh button).

On macOS all native access goes through `macos/Runner/NetworkPlugin.swift`
on MethodChannel `netnatscan/network` — Dart cannot read the ARP table or
netmasks, and the sandbox blocks subprocesses (`ping`, `arp`).

On Windows there is no plugin and no sandbox — `lib/services/` implements
the same channel surface in pure Dart:

- `net_channel.dart` — dispatch facade. Every service calls
  `NetChannel.invoke*`/`toolsEvents`; on Windows it routes to the FFI
  backend, elsewhere to the real channels. Tests always take the channel
  path (`FLUTTER_TEST` env) so `setMockMethodCallHandler` mocks still work.
- `win32_ffi.dart` — hand-bound structs + syscalls (iphlpapi
  `GetIpNetTable2`/`GetIfTable2`/`GetBestRoute2`/`Icmp*`, kernel32
  `WaitForMultipleObjects`/`CreateEventW`, ws2_32, user32 `MessageBeep`)
  on top of package:win32's generated surface.
- `win32_backend.dart` — `getNetworkInfo`/`getArpTable`/`getNdpTable`/
  `triggerNdp`/`getConnectionInfo`/`getWifiNetworks` via
  GetAdaptersAddresses + registry (proxy/DHCP) + wlanapi.
- `win32_wlan.dart` — WLAN scan + current-connection metadata
  (`WlanGetNetworkBssList`/`WlanQueryInterface`), RSN/WPA IE parsing.
- `win32_tools.dart` — ping/route jobs in a spawned isolate, events via
  a broadcast Stream. Stop is cooperative (control port + `_cancelled`
  polled between ≤50 ms wait slices).

- **LAN Scan** — UDP blast → ARP/NDP table → mDNS/SSDP/NBNS/PTR/TLS
  enrichment with scored name pool + standby detection.
  Details: `docs/scan-pipeline.md`.
- **Wi-Fi** — nearby BSSes via CoreWLAN `scanForNetworks` + private
  `CWFScanResult`/`scanRecord` enrichment; tap → detail screen.
  Details: `docs/wifi.md`.
- **Connection** — current uplink: Wi-Fi metadata, interfaces, DNS,
  proxies, DHCP, counters. Details: `docs/wifi.md`.
- **Tools** — ping (ICMP/UDP/TCP) + traceroute, run entirely in-process
  in `NetworkPlugin.swift` (`ToolEngine`/`PingJob`/`RouteJob`). Progress
  streams over EventChannel `netnatscan/tools_events`; run history
  persists to `tool_history.json`. ICMP uses `SOCK_DGRAM` (sandbox-safe);
  note macOS prepends the IPv4 header on received datagrams — `icmpOffset`
  skips it. `SOCK_RAW` is EPERM on this system, so UDP-probe mode falls
  back to ICMP with a note.
- **Private API inventory** — verified CoreWLAN private surface +
  `apple80211_var.h` enum ground truth: `docs/private-apis.md`.

## Entitlements

`network.client` + `network.server` + `personal-information.location`
(both DebugProfile and Release — location is needed because CoreWLAN
redacts SSID/BSSID without it; `NSLocationWhenInUseUsageDescription` +
legacy `NSLocationUsageDescription` in Info.plist).
`NSLocalNetworkUsageDescription` + `NSBonjourServices` in Info.plist.
The sandbox itself can be dropped if a private API needs it — no App
Store requirement (see top of file).
New `.swift` files must be added to `macos/Runner.xcodeproj/project.pbxproj`
manually (4 places: PBXBuildFile, PBXFileReference, Runner group, Sources phase).

## Commands

```bash
flutter pub get
flutter analyze          # must be clean
flutter test
flutter build macos --debug
open build/macos/Build/Products/Debug/netnatscan.app

flutter build windows --debug
build\windows\x64\runner\Debug\netnatscan.exe
dart run tool/smoke_win32.dart   # exercises the FFI backend without the UI
```

## Gotchas

- `sysctl` route dump: `NET_RT_FLAGS` requires a nonzero flag (EINVAL with 0);
  use `NET_RT_DUMP` for the full table, `RTF_LLINFO` for ARP.
- `sockaddr_dl.sdl_data` is only 12 bytes — check `sdl_nlen + sdl_alen <= 12`
  before reading the MAC (long interface names like `bridge0` overflow it).
- `NetworkScanner` is a `ChangeNotifier` owned by `ScanScreen` — dispose
  it on unmount or the passive mDNS loop leaks; in-flight async work
  notifies through `_notify()` so listeners aren't touched after dispose.
- Widget tests: `find.text` (default `skipOffstage`) only traverses
  onstage children — `IndexedStack` keeps hidden tabs alive but skipped,
  and `ListView` children outside the paint extent are skipped too.
  Scope with `find.descendant(..., skipOffstage: false)` or enlarge
  `tester.view.physicalSize` so everything builds.
- Windows FFI: **never free a buffer while a native call may still write
  it.** Async `IcmpSendEcho2` writes the reply buffer on completion —
  `_drainProbes` waits for every outstanding probe's event before the
  arena frees, even on cancel, or the heap corrupts (crashed
  `MIB_IPNET_ROW2.get:State` in unrelated calls before this was fixed).
  `Isolate.kill` is the last-resort fallback only.
- Windows FFI: GetLastError is not reliable across FFI calls — the
  trampoline can clobber it. `IcmpSendEcho2` returning 0 is treated as
  pending unconditionally; a real send failure just never signals the
  event and resolves as a timeout.
- Windows FFI: wait events must be **manual-reset** — an auto-reset
  event's signal is consumed by `WaitForMultipleObjects` before the
  caller can re-check it.
- `SO_REUSEPORT` doesn't exist on Windows — `RawDatagramSocket.bind`
  throws. The mDNS listener socket uses `reusePort: !Platform.isWindows`
  (SO_REUSEADDR alone suffices there).
- Windows socket errno ≠ POSIX: ECONNREFUSED is 10061 (not 61),
  ECONNRESET is 10054 (not 54) — see `_refusedOrReset` in
  `network_scanner.dart`.
- Windows Wi-Fi enrichment gaps vs macOS private APIs: no per-BSS noise
  floor or MLO flags (wlanapi doesn't expose them); security detail comes
  from RSN/WPA IE parsing + the default auth/cipher pair.
