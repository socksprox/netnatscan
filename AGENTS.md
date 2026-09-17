# AGENTS.md - netnatscan

Flutter macOS app: LAN device scanner in the style of iOS "NetAnalyzer".

**Not targeting the App Store** — private APIs, disabling the sandbox,
and subprocesses are all fair game. **Policy: use the public API when it
can deliver the data; private API is fine when it can't.** Guard every
private call (`responds(to:)` / nil checks) and degrade gracefully —
selectors can vanish across macOS versions. See "Private APIs" below for
the verified inventory.

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
   IPv6 twin: `triggerNdp` sends UDP to all-nodes `ff02::1` (native — Dart
   can't send link-scoped multicast) so answering hosts land in the NDP
   table via inbound NS; `getNdpTable` reads the same LLINFO dump with
   `AF_INET6` → `ipv6Addresses`, matched by MAC. mDNS AAAA records feed
   `ipv6Addresses` too (SRV host's AAAA attaches to the device its A hits).
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

## App shell

`lib/screens/main_navigation_screen.dart` hosts an `IndexedStack` of tabs
(currently: `ScanScreen`, `ConnectionInfoScreen`) so tab state survives
switches. `lib/widgets/app_navigation.dart` is the responsive nav —
Shadowfly-admin style: vertical sidebar when the window is ≥ ~1024px
wide, `BottomNavigationBar` below that. Each tab keeps its own
`CustomAppBar`.

## Connection tab

`lib/screens/connection_info_screen.dart` +
`lib/services/connection_info_service.dart`: shows everything knowable
about the current uplink — Wi-Fi SSID/BSSID/security/RSSI/channel/PHY,
interfaces (addresses, MAC, MTU, link speed), DNS/search domains,
proxies, DHCP lease, gateways v4/v6, boot time/uptime, public IP
(api.ipify.org, skipped under `FLUTTER_TEST`), and since-boot rx/tx
counters with live rates (2s ticker diffs successive samples).

`getConnectionInfo` on the same `netnatscan/network` channel returns one
map from `NetworkPlugin.swift`: CoreWLAN (`CWWiFiClient`) for Wi-Fi
metadata, `getifaddrs` for addresses, `NET_RT_IFLIST2` for 64-bit
interface counters (filter records by `RTM_IFINFO2` — the dump
interleaves address records that decode to garbage), `SCDynamicStore`
for DNS/proxies/DHCP (`State:/Network/Service/<uuid>/DHCP`, uuid via
`State:/Network/Global/IPv4` → `PrimaryService`).

Wi-Fi `security` is the coarse `CWSecurity` class ("WPA2 Personal");
`securityDetail` is the precise label ("WPA2-PSK (CCMP-128)") parsed
from the private `CWNetwork.scanRecord` accessor — its `RSN_IE`/`WPA_IE`
dicts carry the real AKM suite list (`IE_KEY_RSN_AUTHSELS`) and cipher
suites (`IE_KEY_RSN_UCIPHERS`/`MCIPHER`) from the beacon IE. Looked up
via `cachedScanResults` matched on BSSID, with a 30s-rate-limited live
scan as fallback; UI prefers `securityDetail` and falls back to
`security`.

## Private APIs

Policy above applies. Inventory below is **verified by runtime probing**
(`class_copyMethodList` + KVC on live objects) unless marked otherwise.

Things no public API exposes:

- **`CWNetwork.scanRecord`** (dict, KVC) — parsed beacon/probe record per
  scanned BSS: `RSN_IE` (`IE_KEY_RSN_AUTHSELS` AKM list,
  `IE_KEY_RSN_UCIPHERS`/`MCIPHER` ciphers, version; `IE_KEY_RSN_CAPS`
  PMF bits when present), `WPA_IE`, `HT_CAPS_IE`, `HT_IE` (secondary
  channel offset → real channel layout), `VHT_CAPS`/`VHT_IE`, `EXT_CAPS`
  (`BSS_TRANS_MGMT` = 802.11v), `RATES`, `RSSI`, `NOISE`, `SNR`,
  `BEACON_INT`, `CAPABILITIES` (privacy bit), `CHANNEL`,
  `CHANNEL_FLAGS`, `PHY_MODE`, `AP_MODE`, `MLO_CONNECTION` /
  `EMLSR_CONNECTION` / `MRSNO_CONNECTION` (Wi-Fi 7), `AGE`,
  `SCAN_RESULT_FROM_PROBE_RSP`. This is the only in-process access to
  real AKM/cipher suites — `CWSecurity` flattens them.
- **`CWNetwork.coreWiFiScanResult`** — object whose `description`
  decodes e.g. `security=wpa2-personal, rsn=[mcast=aes_ccm, bip=none,
  ucast={aes_ccm}, auths={psk}, mfp=no, caps=0x0], channel=2g11/20,
  phy=n, rssi=-83, wasConnectedDuringSleep=0, bi=100, age=…` — includes
  PMF (`mfp`) + BIP management cipher that `RSN_IE` alone doesn't give.
  Structured accessors on its class not yet enumerated.
- **`CWInterface.IO80211ControllerInfo`** — chipset identity:
  ManufacturerID (0x14E4 Broadcom), ProductID, module string, subsystem
  vendor. No public equivalent.
- **`CWInterface.powerDebugInfo`** — huge radio-power counters dict:
  assoc sleep duration, per-band scan counts/durations, ARP-offload
  activity, AWDL awake duration, …
- **`CWInterface.eapolClient`** — `CWEAPOLClient` object (supplicant
  state for enterprise networks; unexplored).
- **`CWInterface.capabilities` / `interfaceCapabilities`** — capability
  list / bitmask; `securityType`/`securityMode` — internal enums
  (128/3 = WPA2 personal on this machine).
- **ANQP** — `queryANQPElements:network:maxAge:…` /
  `queryANQPCacheWithElements:` — 802.11u/Passpoint venue+operator
  metadata from hotspot APs.
- **Trimmed scan properties** — `cachedTrimmedScanResultsWithProperties:`,
  `queryScanCacheWithChannels:…trimmedScanResultProperties:` — request
  specific fields per network; likely the way to populate
  `ieData`/`informationElementData` (raw IE blob — nil in normal cached
  results).
- **`CWNetwork.wasConnectedDuringSleep`**, `accessoryFriendlyName`,
  `hasInterworkingIE` — extra per-network flags.
- **`CWInterface` control surface** (not needed, but exists):
  `startHostAPModeWithSSID:securityType:channel:password:` (host AP
  mode!), `associateToEnterpriseNetwork:…` variants, `enableIBSS…`,
  `clearScanCache`, `initWithInterfaceName:xpcClient:legacy:` (raw
  `CWXPCClient` → airportd).
- **`Apple80211` private framework** (dlopen; *not yet verified in-app*):
  `Apple80211Open`/`BindToInterface`/`Get`/`Set`/`Scan` — per-chain
  RSSI/noise (`RSSI_CTL_LIST`), MCS index, tx rate/PHY rate, supported
  channel list, reg domain. Wraps the airportd XPC — likely needs the
  sandbox off.

Public-but-unused so far: `startMonitoringEventWithName:` (CWEventType
→ roam/link-quality/power/disassociation event stream).

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
- Device type classification lives in `lib/models/network_device.dart`.
