# Private API inventory

Policy (from AGENTS.md): **public API is the baseline; private APIs are
optional enrichment.** Guard every private call (`responds(to:)` / nil
checks) and always emit the public value too, so the app works fully
even if every private call returns nil — selectors can and will vanish
across macOS versions.

Inventory below is **verified by runtime probing** (`class_copyMethodList`
+ KVC on live objects) unless marked otherwise.

## CoreWLAN — `CWNetwork` / `CWFScanResult`

- **`CWNetwork.coreWiFiScanResult` → `CWFScanResult`** — the rich
  structured object (this is what `getWifiNetworks` uses). Getters
  verified live: `RSNAuthSelectors`/`RSNUnicastCiphers`/`RSNMulticast-
  Cipher`/`RSNBroadcastCipher` (BIP mgmt cipher!)/`RSNCapabilities`,
  `isWPA/2/3`, `isPSK`, `isEAP`, `isOWE`, `isOpen`, `isWEP`, `isWAPI`,
  `isMFPCapable`/`isMFPRequired`, `isPasspoint`, `isHotspot`,
  `isMetered`, `isPersonalHotspot`, `isNonTransmittedBSSID`,
  `isWiFi6E`, `isAppleSWAP`, `isAssociationDisallowed`,
  `isFILSDiscoveryFrame`, `isUnconfiguredAirPortBaseStation`,
  `isESS`/`isIBSS`, `hasTKIPCipher`, `hasWEP40/104Cipher`,
  `supportsWPS`/`AirPlay`/`AirPlay2`/`AirPrint`/`HomeKit`/`CarPlay`/
  `WoW`/`MFi`, `providesInternetAccess`, `wasConnectedDuringSleep`,
  `beaconInterval`, `age` (ms), `signalStrength` (normalized 0–1),
  `channel` (decoded spec string like `"5g36/80"`), `APMode`,
  `accessNetworkType`, `rsnPriority`, `networkFlags`, `countryCode`,
  Passpoint/venue fields (`venueGroup`/`venueType`/`venueURLList`/
  `operatorFriendlyNameList`/`domainNameList`/`roamingConsortiumList`/
  `NAIRealmNameList`/`ANQPResponse`), identity (`manufacturerName`/
  `modelName`/`displayName`/`deviceID`/`HESSID`/`primaryMAC`/
  `bluetoothMAC`), `RNRBSSList`/`RNRChannelList` (RNR neighbours),
  `informationElementData` (raw IEs — nil unless requested via
  trimmed scan properties), `__descriptionForRSNAuthSel:`/
  `__descriptionForRSNCipher:` (Apple's own name decoders).
  `description` decodes e.g. `security=wpa2-personal, rsn=[mcast=
  aes_ccm, bip=none, ucast={aes_ccm}, auths={psk}, mfp=no, caps=0x0],
  channel=2g11/20, phy=n, rssi=-83, wasConnectedDuringSleep=0, bi=100`
  — note `phy=` there is the received-frame PHY, NOT the fastest mode.
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
- **`CWNetwork.wasConnectedDuringSleep`**, `accessoryFriendlyName`,
  `hasInterworkingIE` — extra per-network flags.
- **ANQP** — `queryANQPElements:network:maxAge:…` /
  `queryANQPCacheWithElements:` — 802.11u/Passpoint venue+operator
  metadata from hotspot APs.
- **Trimmed scan properties** — `cachedTrimmedScanResultsWithProperties:`,
  `queryScanCacheWithChannels:…trimmedScanResultProperties:` — request
  specific fields per network; likely the way to populate
  `ieData`/`informationElementData` (raw IE blob — nil in normal cached
  results).

## CoreWLAN — `CWInterface`

- **`IO80211ControllerInfo`** — chipset identity: ManufacturerID
  (0x14E4 Broadcom), ProductID, module string, subsystem vendor.
  No public equivalent.
- **`powerDebugInfo`** — huge radio-power counters dict: assoc sleep
  duration, per-band scan counts/durations, ARP-offload activity,
  AWDL awake duration, …
- **`eapolClient`** — `CWEAPOLClient` object (supplicant state for
  enterprise networks; unexplored).
- **`capabilities` / `interfaceCapabilities`** — capability list /
  bitmask; `securityType`/`securityMode` — internal enums (128/3 =
  WPA2 personal on this machine).
- **Control surface** (not needed, but exists):
  `startHostAPModeWithSSID:securityType:channel:password:` (host AP
  mode!), `associateToEnterpriseNetwork:…` variants, `enableIBSS…`,
  `clearScanCache`, `initWithInterfaceName:xpcClient:legacy:` (raw
  `CWXPCClient` → airportd).

## Enum/bitfield ground truth

Apple's APSL header `apple80211_var.h` (mirrored in
OpenIntelWireless/itlwm `include/Airport/`) defines the scan-record
enums — use it before inventing decode tables:

- `apple80211_apmode`: 0 unknown, 1 IBSS, 2 infra, 3 any. (`apMode`
  stays in the `WifiNetwork` model but is not shown — always
  "Infrastructure".)
- `apple80211_phymode`: `2 << (n-1)` per generation — bit1=a, 2=b,
  3=g, 4=n, 5=TurboA, 6=TurboG, 7=ac, 8=ax; bit9 presumed be.
  `supportedPHYModes`/`fastestSupportedPHYMode`/`slowestSupportedPHYMode`
  on CWFScanResult use this mask (`phyName`/`phyMaskString` in
  NetworkPlugin.swift decode it; unknown bits → `mode-N`).
- `apple80211_channel_flag`: 0x8=2GHz, 0x10=5GHz, 0x20=IBSS,
  0x40=HostAP, 0x80=active-scan, 0x100=DFS, 0x200=ext-above,
  0x400=80MHz, 0x800=160MHz.
- `accessNetworkType`: standard 802.11u ANQP enum (1 private+guest,
  2 chargeable, 3 free public, 4 personal, 5 emergency, 14 test,
  15 wildcard); 0=private is omitted in the UI.

## Beyond CoreWLAN

- **`Apple80211` private framework** (dlopen; *not yet verified
  in-app*): `Apple80211Open`/`BindToInterface`/`Get`/`Set`/`Scan` —
  per-chain RSSI/noise (`RSSI_CTL_LIST`), MCS index, tx rate/PHY rate,
  supported channel list, reg domain. Wraps the airportd XPC — likely
  needs the sandbox off.
- **Public-but-unused**: `startMonitoringEventWithName:` (CWEventType
  → roam/link-quality/power/disassociation event stream).
