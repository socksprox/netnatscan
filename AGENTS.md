# AGENTS.md - netnatscan

Flutter macOS app: LAN device scanner in the style of iOS "NetAnalyzer".

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

All native access goes through `macos/Runner/NetworkPlugin.swift` on
MethodChannel `netnatscan/network` — Dart cannot read the ARP table or
netmasks, and the sandbox blocks subprocesses (`ping`, `arp`).

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
flutter analyze          # must be clean (1 pre-existing info lint is OK)
flutter test
flutter build macos --debug
open build/macos/Build/Products/Debug/netnatscan.app
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
