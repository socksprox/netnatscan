# Wi-Fi & Connection tabs

Both ride MethodChannel `netnatscan/network` →
`macos/Runner/NetworkPlugin.swift`.

## Wi-Fi tab (nearby networks)

`lib/screens/wifi_networks_screen.dart` +
`lib/services/wifi_networks_service.dart`: nearby BSSes via
`getWifiNetworks` — a real `scanForNetworks` per call (dispatched
off-main, blocks ~1-2s), ticking every 10s.

Public baseline per network: SSID (null → "Hidden network"), BSSID →
OUI vendor, RSSI/noise/SNR, channel/band/width, `ibss` ad-hoc flag,
`isCurrent` (BSSID match → "Connected" badge + sorted first, then
RSSI desc). Coarse security label from public `supportsSecurity`
probes — transition APs answer true for both generations →
"WPA2/WPA3 Personal".

On top of that baseline, `enrichFromPrivate` layers the private
`CWFScanResult` (`coreWiFiScanResult`) + `scanRecord` fields — every
one optional, all `responds(to:)`-guarded: `securityDetail` (real
AKM/cipher + PMF/BIP), `phyFastest`/`phySupported` (bitmask decode),
`signalStrength` (0–1, drives bars), `channelSpec` (`"5g36/80"`),
`beaconInterval`, `ageMs`, `apMode`, `maxStreams` (VHT/HT MCS maps),
`vhtMaxWidth`, `vhtCenterChan`, `secondaryChanOffset`, `rates`,
`channelFlags`, `capabilities`, `fromProbeRsp`, `oweMultiSsid`,
`wasConnectedDuringSleep`, `filsDiscovery`, `unconfiguredAP`,
`mlo`/`emlsr`/`mrsno` (Wi-Fi 7), `tags` (Passpoint/Hotspot/WPS/
AirPlay/Metered/TKIP/…), plus venue/identity fields when present
(manufacturerName, modelName, venue, operator, …). Tapping a card
opens `wifi_network_detail_screen.dart` with the full dump in
copyable sections; the card shows `securityDetail ?? security` plus
a feature line. See `docs/private-apis.md` for the field inventory.

## Connection tab (current uplink)

`lib/screens/connection_info_screen.dart` +
`lib/services/connection_info_service.dart`: everything knowable
about the current uplink — Wi-Fi SSID/BSSID/security/RSSI/channel/
PHY, interfaces (addresses, MAC, MTU, link speed), DNS/search
domains, proxies, DHCP lease, gateways v4/v6, boot time/uptime,
public IP (api.ipify.org, skipped under `FLUTTER_TEST`), and
since-boot rx/tx counters with live rates (2s ticker diffs
successive samples).

`getConnectionInfo` returns one map from `NetworkPlugin.swift`:
CoreWLAN (`CWWiFiClient`) for Wi-Fi metadata, `getifaddrs` for
addresses, `NET_RT_IFLIST2` for 64-bit interface counters (filter
records by `RTM_IFINFO2` — the dump interleaves address records
that decode to garbage), `SCDynamicStore` for DNS/proxies/DHCP
(`State:/Network/Service/<uuid>/DHCP`, uuid via
`State:/Network/Global/IPv4` → `PrimaryService`).

Wi-Fi `security` is the coarse `CWSecurity` class ("WPA2 Personal");
`securityDetail` is the precise label ("WPA2-PSK (CCMP-128)") parsed
from the private `CWNetwork.scanRecord` accessor — its
`RSN_IE`/`WPA_IE` dicts carry the real AKM suite list
(`IE_KEY_RSN_AUTHSELS`) and cipher suites
(`IE_KEY_RSN_UCIPHERS`/`MCIPHER`) from the beacon IE. Looked up via
`cachedScanResults` matched on BSSID, with a 30s-rate-limited live
scan as fallback; UI prefers `securityDetail` and falls back to
`security`.
