# AGENTS.md - netnatscan

Flutter macOS app: LAN device scanner in the style of iOS "NetAnalyzer".

## Design

- UI rules: `.devin/rules/ui-design.md` — TDesign-styled components copied from
  `/Users/tamino/Code/N3DS/SFYGameTransferrer`. **No `tdesign_flutter` package**;
  `lib/widgets/tdesign.dart` locally re-implements `TDText`/`TDTheme`/`TDToast`.
- Reference implementation for scanning logic (non-UI):
  `/Users/tamino/Downloads/netscli-main` (Rust).

## How scanning works

`lib/services/network_scanner.dart`:

1. `getNetworkInfo` (MethodChannel `netnatscan/network`) → interfaces +
   default gateway from native Swift (`macos/Runner/NetworkPlugin.swift`)
   via `getifaddrs` + PF_ROUTE sysctl dump. All in-process, App Sandbox safe.
2. UDP datagram blast to every host in the subnet — any L2-bound packet
   forces kernel ARP resolution; live hosts must answer ARP.
3. `getArpTable` → sysctl `NET_RT_FLAGS`/`RTF_LLINFO` dump → live devices
   with real MACs (definitive for LAN discovery; catches hosts that ignore ICMP).
4. Enrichment — every protocol feeds one scored name-candidate pool
   (`_addNameCandidate`/`_finalizeNames`; PTR 40 > UPnP friendlyName 35 >
   host/instance/NetBIOS 30 > HTTP title/UPnP model 22, cryptic penalty,
   shortest wins ties):
   - mDNS/Bonjour (raw UDP 5353, `mdns_discovery.dart`)
   - SSDP/UPnP (`ssdp_discovery.dart`): M-SEARCH to 239.255.255.250:1900
     + unicast per target, then HTTP-fetch each LOCATION description XML
     → friendlyName/manufacturer/model/deviceType (regex-extracted, no
     XML dep)
   - NBNS (`nbns_discovery.dart`): unicast UDP/137 wildcard NBSTAT →
     NetBIOS name table (Windows/Samba/printers); unique <00> name is
     the hostname
   - OUI vendor, reverse-DNS PTR, light TCP RTT (443/80/22), TLS cert
     subject on 443/8443
   - Liveness: `lastSeenAt` is stamped ONLY by real answers (mDNS/PTR/
     NBNS/SSDP/TLS/HTTP); `_applyNameCache` treats <60s-old as live,
     older/silent → cache restore + `isStandby`
5. `DeviceNameCache` (`lib/services/name_cache.dart`): MAC → name/types
   persisted to `device_names.json`. Devices silent on mDNS get their
   identity restored and `isStandby = true` (sleeping phones keep their
   ARP entry via the Wi-Fi chip but stop answering Bonjour — verified:
   nothing wakes them remotely, not ICMP/TCP/UDP/unicast-mDNS/AWDL).
6. Passive loop (`_startPassiveMdns`): a continuous 45s `browse` that
   re-queries silent devices each cycle — catches wake announcements
   opportunistically and clears the standby flag when a device answers.
   Attribution uses `resolvedIps` (SRV→A proven) not packet source —
   iPhones mirror other devices' PTRs.
7. Explicit port scan: `scanPorts` runs on demand per device — device
   card context menu (right-click / long-press) → "Port scan", or the
   Port scan section in the detail view. `commonScanPorts` (20 ports,
   ~1s) and `extendedScanPorts` (49 ports) are curated by service; open
   ports feed classification (62078→iPhone, 554→camera, 9100/631→
   printer, 8008/9→Chromecast, 445/548→computer, 8291→MikroTik). Open
   web ports (80/8080/8000/8888) additionally get `GET /` → Server
   header + `<title>` into the name pool (`_probeHttp`).

Native code is required — Dart cannot read the ARP table or netmasks, and
the sandbox blocks subprocesses (`ping`, `arp`).

## Entitlements

`network.client` + `network.server` (both DebugProfile and Release).
`NSLocalNetworkUsageDescription` + `NSBonjourServices` in Info.plist.
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
- Device type classification lives in `lib/models/network_device.dart`.
