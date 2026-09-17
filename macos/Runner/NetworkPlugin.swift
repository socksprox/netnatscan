import Cocoa
import FlutterMacOS
import Darwin
import CoreLocation
import CoreWLAN
import SystemConfiguration

/// Exposes link-local network facts that dart:io cannot reach on macOS:
/// interface list with IPv4/netmask/MAC, the default route, and the ARP
/// (neighbour) table. Everything is done in-process via getifaddrs(3) and
/// the PF_ROUTE sysctl dump so it works inside the App Sandbox — no
/// subprocesses, no raw-socket privileges.
class NetworkPlugin: NSObject, FlutterPlugin {
  static let channelName = "netnatscan/network"

  static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(
      name: channelName, binaryMessenger: registrar.messenger)
    let instance = NetworkPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "getNetworkInfo":
      result(getNetworkInfo())
    case "getArpTable":
      result(getArpTable())
    case "getNdpTable":
      result(getNdpTable())
    case "triggerNdp":
      triggerNdp(interface: call.arguments as? String)
      result(nil)
    case "getConnectionInfo":
      result(getConnectionInfo())
    case "getWifiNetworks":
      // Location prompting must happen on the main thread; the scan
      // itself blocks ~1-2s, so run it on a worker queue.
      requestLocationIfNeeded(CWWiFiClient.shared().interface())
      DispatchQueue.global(qos: .userInitiated).async {
        result(self.getWifiNetworks())
      }
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  // MARK: - getNetworkInfo

  /// -> {
  ///   "interfaces": [{"name","ip","netmask","mac"?,"ipv6"?,...}],
  ///   "defaultGateway": String?,
  ///   "defaultInterface": String?
  /// }
  private func getNetworkInfo() -> [String: Any] {
    var macByName: [String: String] = [:]
    var ipv6ByName: [String: [String]] = [:]
    var interfaces: [[String: Any]] = []

    var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else {
      return ["interfaces": [], "defaultGateway": NSNull(), "defaultInterface": NSNull()]
    }
    defer { freeifaddrs(ifaddrPtr) }

    var cursor: UnsafeMutablePointer<ifaddrs>? = first
    while let ifa = cursor?.pointee {
      defer { cursor = ifa.ifa_next }
      guard let sa = ifa.ifa_addr else { continue }
      let name = String(cString: ifa.ifa_name)
      let family = sa.pointee.sa_family

      if family == UInt8(AF_LINK) {
        if let mac = linkAddress(from: sa) {
          macByName[name] = mac
        }
      } else if family == UInt8(AF_INET6) {
        let bytes = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
          sin6 in withUnsafeBytes(of: sin6.pointee.sin6_addr) { Array($0) }
        }
        if let ip = ipv6String(bytes, scopeIfname: name), ip != "::1" {
          ipv6ByName[name, default: []].append(ip)
        }
      } else if family == UInt8(AF_INET) {
        let ip = ipv4String(from: sa)
        var mask: String? = nil
        if let netmask = ifa.ifa_netmask {
          mask = ipv4String(from: netmask)
        }
        if let ip {
          interfaces.append([
            "name": name,
            "ip": ip,
            "netmask": mask ?? NSNull(),
            "isUp": (ifa.ifa_flags & UInt32(IFF_UP)) != 0,
            "isLoopback": (ifa.ifa_flags & UInt32(IFF_LOOPBACK)) != 0,
          ])
        }
      }
    }

    // Attach MACs + IPv6 addresses to IPv4 rows.
    for i in interfaces.indices {
      let name = interfaces[i]["name"] as? String ?? ""
      if let mac = macByName[name] {
        interfaces[i]["mac"] = mac
      }
      if let v6 = ipv6ByName[name], !v6.isEmpty {
        interfaces[i]["ipv6"] = v6
      }
    }

    let route = defaultRoute()
    return [
      "interfaces": interfaces,
      "defaultGateway": route.gateway ?? NSNull(),
      "defaultInterface": route.interface ?? NSNull(),
    ]
  }

  // MARK: - getConnectionInfo

  /// Everything about the *current* uplink in one call, all in-process:
  /// -> {
  ///   "hostname": String?,
  ///   "primaryInterface": String?,
  ///   "networkType": "wifi"|"ethernet"|"other"|"offline",
  ///   "defaultGateway": String?, "ipv6Gateway": String?,
  ///   "wifi": {ssid?,bssid?,security,securityDetail?,rssi?,noise?,transmitRate,
  ///            channel?,channelBand?,channelWidth?,phyMode,
  ///            countryCode?,mac?,interfaceName}?,
  ///   "interfaces": {name: {index,flags,mtu,baudrate,type?,mac?,
  ///            rxBytes,txBytes,rxPackets,txPackets,rxErrors,txErrors,
  ///            rxQDrops,collisions}},
  ///   "dnsServers": [String], "searchDomains": [String],
  ///   "proxies": {HTTPEnable?,HTTPProxy?,HTTPPort?,...},
  ///   "dhcp": {LeaseStartTime? (epoch), ServerIdentifier?, ...},
  ///   "bootTime": Double?, "uptimeSeconds": Double?
  /// }
  private func getConnectionInfo() -> [String: Any] {
    var payload: [String: Any] = [:]

    var host = [CChar](repeating: 0, count: Int(MAXHOSTNAMELEN))
    if gethostname(&host, host.count) == 0 {
      payload["hostname"] = String(cString: host)
    }

    let route = defaultRoute()
    payload["defaultGateway"] = route.gateway ?? NSNull()
    payload["ipv6Gateway"] = defaultGatewayV6() ?? NSNull()

    let stats = interfaceStats()
    payload["interfaces"] = stats

    let primary = route.interface ?? firstUpInterface(stats)
    payload["primaryInterface"] = primary ?? NSNull()

    // CWWiFiClient answers nil for non-Wi-Fi interface names, so a hit is
    // itself the Wi-Fi detection (Wi-Fi MACs report sdl_type IFT_ETHER too).
    let wifi = wifiInfo(for: primary)
    if let wifi {
      payload["wifi"] = wifi
    }
    payload["networkType"] = networkType(
      primary: primary, wifi: wifi, stats: stats)

    if let store = SCDynamicStoreCreate(nil, "netnatscan" as CFString, nil, nil) {
      let dns =
        SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString)
        as? [String: Any]
      payload["dnsServers"] = dns?["ServerAddresses"] as? [String] ?? []
      payload["searchDomains"] = dns?["SearchDomains"] as? [String] ?? []
      payload["proxies"] = proxySettings(store: store)
      payload["dhcp"] = dhcpInfo(store: store)
    }

    let boot = bootTime()
    payload["bootTime"] = boot ?? NSNull()
    if let boot {
      payload["uptimeSeconds"] = max(
        0, Date().timeIntervalSince1970 - boot)
    }
    return payload
  }

  /// 64-bit interface counters via the NET_RT_IFLIST2 sysctl dump — the
  /// same PF_ROUTE mechanism as the route/ARP walks, but each record is
  /// an if_msghdr2 carrying an if_data64 plus a sockaddr_dl (RTA_IFP)
  /// with the interface name, link type and MAC. All in-process.
  private func interfaceStats() -> [String: [String: Any]] {
    guard let dump = sysctlDump(op: NET_RT_IFLIST2, flags: 0, family: 0)
    else { return [:] }
    var out: [String: [String: Any]] = [:]
    forEachIfEntry(in: dump) { ifm, addrs in
      // The dump interleaves address records (RTM_NEWADDR/NEWMADDR2)
      // with interface records — only RTM_IFINFO2 carries if_data64.
      guard Int(ifm.pointee.ifm_type) == Int(RTM_IFINFO2),
        let name = ifName(UInt32(ifm.pointee.ifm_index))
      else { return }
      let d = ifm.pointee.ifm_data
      var m: [String: Any] = [
        "index": Int(ifm.pointee.ifm_index),
        "flags": Int(ifm.pointee.ifm_flags),
        "mtu": Int(d.ifi_mtu),
        "baudrate": Int(d.ifi_baudrate),
        "rxPackets": Int(d.ifi_ipackets),
        "rxErrors": Int(d.ifi_ierrors),
        "txPackets": Int(d.ifi_opackets),
        "txErrors": Int(d.ifi_oerrors),
        "rxBytes": Int(d.ifi_ibytes),
        "txBytes": Int(d.ifi_obytes),
        "rxQDrops": Int(d.ifi_iqdrops),
        "collisions": Int(d.ifi_collisions),
      ]
      if let sdlOffset = addrs[Int(RTA_IFP)],
        let sdlBytes = sockaddrDLBytes(in: dump, at: sdlOffset),
        let dl = parseSockaddrDL(sdlBytes)
      {
        m["type"] = dl.type
        if dl.addr.count == 6 {
          m["mac"] = dl.addr.map { String(format: "%02x", $0) }
            .joined(separator: ":")
        }
      }
      out[name] = m
    }
    return out
  }

  /// Fallback primary when there is no default route: lowest-indexed
  /// up, non-loopback interface.
  private func firstUpInterface(_ stats: [String: [String: Any]]) -> String? {
    let sorted = stats.sorted {
      ($0.value["index"] as? Int ?? 0) < ($1.value["index"] as? Int ?? 0)
    }
    for (name, s) in sorted {
      let flags = s["flags"] as? Int ?? 0
      let up = (flags & Int(IFF_UP)) != 0
      let loop = (flags & Int(IFF_LOOPBACK)) != 0
      if up && !loop { return name }
    }
    return nil
  }

  private func networkType(
    primary: String?, wifi: [String: Any]?, stats: [String: [String: Any]]
  ) -> String {
    guard let primary else { return "offline" }
    if wifi != nil { return "wifi" }
    if let t = stats[primary]?["type"] as? Int {
      if t == Int(IFT_ETHER) { return "ethernet" }
      if t == Int(IFT_LOOP) { return "loopback" }
    }
    return "other"
  }

  /// Held lazily for the location grant — created on the main thread
  /// (plugin calls arrive there) and kept alive for the app lifetime.
  private lazy var locationManager = CLLocationManager()

  /// CoreWLAN redacts ssid/bssid until the app holds Location Services —
  /// ask once; the periodic refresh picks the fields up after approval.
  private func requestLocationIfNeeded(_ w: CWInterface?) {
    guard let w, w.ssid() == nil,
      locationManager.authorizationStatus == .notDetermined
    else { return }
    locationManager.requestWhenInUseAuthorization()
  }

  // MARK: - getWifiNetworks

  /// Nearby BSSes from a real scan — public CWNetwork fields only.
  /// (The private scanRecord enrichment — real AKM/cipher suites, PHY
  /// caps, MLO flags — is a planned later pass; see "Private APIs".)
  /// -> {"interfaceName": String?,
  ///     "networks": [{ssid?,bssid?,rssi,noise,channel?,band?,width?,
  ///                   security,ibss,isCurrent}]}
  private func getWifiNetworks() -> [String: Any] {
    guard let w = CWWiFiClient.shared().interface(),
      w.serviceActive()
    else { return ["interfaceName": NSNull(), "networks": []] }
    let myBssid = w.bssid()
    var nets: [[String: Any]] = []
    for n in (try? w.scanForNetworks(withSSID: nil)) ?? [] {
      var m: [String: Any] = [
        "ssid": n.ssid ?? NSNull(),
        "bssid": n.bssid ?? NSNull(),
        "rssi": n.rssiValue,
        "noise": n.noiseMeasurement,
        "ibss": n.ibss,
        "security": networkSecurityLabel(n),
        "isCurrent": myBssid != nil && n.bssid == myBssid,
      ]
      if let ch = n.wlanChannel {
        m["channel"] = ch.channelNumber
        m["band"] = channelBandString(ch.channelBand)
        if #available(macOS 10.15, *) {
          m["width"] = channelWidthString(ch.channelWidth)
        }
      }
      enrichFromPrivate(&m, n)
      nets.append(m)
    }
    return ["interfaceName": w.interfaceName ?? NSNull(), "networks": nets]
  }

  /// Private enrichment — `CWFScanResult` (via `coreWiFiScanResult`)
  /// and `CWNetwork.scanRecord`. Every field is optional: the public
  /// values above are always present, and every access here is guarded
  /// with responds(to:)/nil checks so a vanished selector degrades to
  /// "field absent" rather than a crash. See "Private APIs" in AGENTS.md.
  private func enrichFromPrivate(_ m: inout [String: Any], _ n: CWNetwork) {
    let csr: NSObject? =
      n.responds(to: NSSelectorFromString("coreWiFiScanResult"))
      ? n.value(forKey: "coreWiFiScanResult") as? NSObject
      : nil
    func g(_ key: String) -> Any? {
      guard let csr, csr.responds(to: NSSelectorFromString(key)) else {
        return nil
      }
      return csr.value(forKey: key)
    }
    func flag(_ key: String) -> Bool {
      (g(key) as? NSNumber)?.boolValue ?? false
    }

    // -- CWFScanResult scalars ------------------------------------------
    if let v = g("signalStrength") as? NSNumber {
      m["signalStrength"] = v.doubleValue
    }
    if let v = g("channel") as? CustomStringConvertible {
      m["channelSpec"] = v.description  // e.g. "5g36/80"
    }
    if let v = g("supportedPHYModes") as? NSNumber {
      let mask = v.intValue
      m["phySupported"] = phyMaskString(mask)
      if let f = g("fastestSupportedPHYMode") as? NSNumber,
        let name = phyName(f.intValue)
      {
        m["phyFastest"] = name
      }
    }
    if let v = g("beaconInterval") as? NSNumber {
      m["beaconInterval"] = v
    }
    if let v = g("age") as? NSNumber { m["ageMs"] = v }
    if let v = g("APMode") as? NSNumber { m["apMode"] = v }
    if let v = g("accessNetworkType") as? NSNumber {
      m["accessNetworkType"] = v
    }
    if let v = g("rsnPriority") as? NSNumber { m["rsnPriority"] = v }
    if flag("wasConnectedDuringSleep") { m["wasConnectedDuringSleep"] = true }
    if flag("isFILSDiscoveryFrame") { m["filsDiscovery"] = true }
    if flag("isUnconfiguredAirPortBaseStation") {
      m["unconfiguredAP"] = true
    }

    // PMF: csr flags + the BIP management cipher — more reliable than
    // the RSN caps bits in the dict (often absent there).
    let bipType = (g("RSNBroadcastCipher") as? NSNumber)?.intValue
    if flag("isMFPRequired") {
      m["pmf"] =
        "required" + (bipType.map { " (\(cipherName($0)))" } ?? "")
    } else if flag("isMFPCapable") {
      m["pmf"] =
        "capable" + (bipType.map { " (\(cipherName($0)))" } ?? "")
    }

    // Notable booleans → a compact tag list the card can badge.
    var tags: [String] = []
    let tagMap: [(String, String)] = [
      ("isPasspoint", "Passpoint"),
      ("isHotspot", "Hotspot 2.0"),
      ("isPersonalHotspot", "Personal hotspot"),
      ("isWiFi6E", "6E"),
      ("isMetered", "Metered"),
      ("isNonTransmittedBSSID", "Non-transmitted BSSID"),
      ("isAssociationDisallowed", "Association disallowed"),
      ("isAppleSWAP", "Apple SWAP"),
      ("isUnauthenticatedEmergencyServiceAccessible", "Emergency services"),
      ("supportsWPS", "WPS"),
      ("supportsAirPlay2", "AirPlay 2"),
      ("supportsAirPrint", "AirPrint"),
      ("supportsHomeKit", "HomeKit"),
      ("supportsCarPlay", "CarPlay"),
      ("providesInternetAccess", "Internet access"),
      ("hasTKIPCipher", "TKIP"),
    ]
    for (key, label) in tagMap where flag(key) {
      tags.append(label)
    }

    // Rarely-populated identity/venue fields — emit when present.
    for (key, out) in [
      ("manufacturerName", "manufacturerName"),
      ("modelName", "modelName"),
      ("displayName", "displayName"),
      ("deviceID", "deviceID"),
      ("HESSID", "hessid"),
      ("primaryMAC", "primaryMAC"),
      ("countryCode", "countryCode"),
      ("accessoryFriendlyName", "friendlyName"),
    ] {
      if let v = g(key) { m[out] = "\(v)" }
    }
    for (key, out) in [
      ("operatorFriendlyNameList", "operatorFriendlyNames"),
      ("venueURLList", "venueURLs"),
      ("domainNameList", "domainNames"),
      ("roamingConsortiumList", "roamingConsortiums"),
      ("NAIRealmNameList", "naiRealms"),
    ] {
      if let v = g(key) as? [Any], !v.isEmpty {
        m[out] = v.map { "\($0)" }
      }
    }
    for (key, out) in [
      ("venueGroup", "venueGroup"), ("venueType", "venueType"),
    ] {
      if let v = g(key) as? NSNumber, v.intValue != 0 {
        m[out] = v
      }
    }

    // -- scanRecord dict -------------------------------------------------
    guard let rec = scanRecord(n) else {
      if !tags.isEmpty { m["tags"] = tags }
      return
    }
    if let detail = describeSecurity(rec) {
      // Prefer the csr PMF flags over the dict caps bits (often absent).
      if let pmf = m["pmf"] as? String, !detail.contains("PMF") {
        m["securityDetail"] = "\(detail), PMF \(pmf)"
      } else {
        m["securityDetail"] = detail
      }
    }
    if let v = rec["RATES"] as? [NSNumber] { m["rates"] = v }
    if let v = rec["CHANNEL_FLAGS"] as? NSNumber {
      m["channelFlags"] = v
    }
    if let v = rec["CAPABILITIES"] as? NSNumber {
      m["capabilities"] = v
    }
    if rec["SCAN_RESULT_FROM_PROBE_RSP"] as? NSNumber != nil {
      m["fromProbeRsp"] =
        (rec["SCAN_RESULT_FROM_PROBE_RSP"] as? NSNumber)?.boolValue ?? false
    }
    if let v = rec["SCAN_RESULT_OWE_MULTI_SSID"] as? NSNumber,
      v.boolValue
    {
      m["oweMultiSsid"] = true
    }
    if let ht = rec["HT_IE"] as? [String: Any],
      let off = ht["HT_SECONDARY_CHAN_OFFSET"] as? NSNumber
    {
      m["secondaryChanOffset"] = off
    }
    if let vht = rec["VHT_IE"] as? [String: Any] {
      if let v = vht["VHT_CENTER_CHAN_SEGMENT0"] as? NSNumber {
        m["vhtCenterChan"] = v
      }
    }
    if let vht = rec["VHT_CAPS"] as? [String: Any] {
      if let caps = vht["VHT_CAPS"] as? NSNumber {
        // Supported channel width set (bits 0-1).
        switch caps.intValue & 3 {
        case 1: m["vhtMaxWidth"] = "160 MHz"
        case 2: m["vhtMaxWidth"] = "160/80+80 MHz"
        default: break
        }
      }
      if let mcs = vht["VHT_SUPPORTED_MCS_SET"] as? Data, mcs.count >= 2 {
        // RX MCS map: 2 bits per spatial stream, 3 = unsupported.
        let rx = Int(mcs[0]) | Int(mcs[1]) << 8
        let streams = (0..<8).filter { (rx >> (2 * $0)) & 3 != 3 }.count
        if streams > 0 { m["maxStreams"] = streams }
      }
    } else if let ht = rec["HT_CAPS_IE"] as? [String: Any],
      let mcs = ht["MCS_SET"] as? Data, mcs.count >= 4
    {
      // HT MCS mask: bytes 0-3 are the per-stream bitmaps.
      let streams = (0..<4).filter { mcs[$0] != 0 }.count
      if streams > 0 { m["maxStreams"] = streams }
    }
    // Wi-Fi 7 multi-link operation flags.
    if (rec["MLO_CONNECTION"] as? NSNumber)?.boolValue == true {
      tags.append("MLO")
      m["mlo"] = true
    }
    if (rec["EMLSR_CONNECTION"] as? NSNumber)?.boolValue == true {
      tags.append("EMLSR")
    }
    if (rec["MRSNO_CONNECTION"] as? NSNumber)?.boolValue == true {
      tags.append("MRSNO")
    }
    if !tags.isEmpty { m["tags"] = tags }
  }

  /// PHY-mode bitmask — apple80211_phymode (apple80211_var.h, APSL):
  /// 2 << (n-1) per generation. bit 9 presumably 802.11be (header
  /// predates Wi-Fi 7).
  private func phyName(_ bit: Int) -> String? {
    switch bit {
    case 1: return "802.11a"
    case 2: return "802.11b"
    case 3: return "802.11g"
    case 4: return "802.11n"
    case 5: return "Turbo A"
    case 6: return "Turbo G"
    case 7: return "802.11ac"
    case 8: return "802.11ax"
    case 9: return "802.11be"
    default: return nil
    }
  }

  private func phyMaskString(_ mask: Int) -> String {
    var out: [String] = []
    for bit in 0..<32 where mask & (1 << bit) != 0 {
      out.append(phyName(bit)?.replacingOccurrences(of: "802.11", with: "")
        ?? "mode-\(bit)")
    }
    return out.joined(separator: "/")
  }

  /// Coarse security via the public supportsSecurity(_:) probes — a
  /// transition AP answers true for both generations, so "WPA2/WPA3"
  /// falls out naturally. (Exact AKM names need scanRecord — later.)
  private func networkSecurityLabel(_ n: CWNetwork) -> String {
    if n.supportsSecurity(.none) { return "Open" }
    if n.supportsSecurity(.WEP) { return "WEP" }
    if n.supportsSecurity(.OWE) { return "OWE" }
    if n.supportsSecurity(.oweTransition) { return "OWE Transition" }
    if n.supportsSecurity(.dynamicWEP) { return "Dynamic WEP" }
    var parts: [String] = []
    var pgens: [String] = []
    if n.supportsSecurity(.wpaPersonal) || n.supportsSecurity(.wpaPersonalMixed) {
      pgens.append("WPA")
    }
    if n.supportsSecurity(.wpa2Personal) || n.supportsSecurity(.personal) {
      pgens.append("WPA2")
    }
    if n.supportsSecurity(.wpa3Personal) { pgens.append("WPA3") }
    if n.supportsSecurity(.wpa3Transition) { pgens = ["WPA2", "WPA3"] }
    if !pgens.isEmpty {
      parts.append(pgens.joined(separator: "/") + " Personal")
    }
    var egens: [String] = []
    if n.supportsSecurity(.wpaEnterprise)
      || n.supportsSecurity(.wpaEnterpriseMixed)
    { egens.append("WPA") }
    if n.supportsSecurity(.wpa2Enterprise)
      || n.supportsSecurity(.enterprise)
    { egens.append("WPA2") }
    if n.supportsSecurity(.wpa3Enterprise) { egens.append("WPA3") }
    if !egens.isEmpty {
      parts.append(egens.joined(separator: "/") + " Enterprise")
    }
    return parts.isEmpty ? "Unknown" : parts.joined(separator: " + ")
  }

  /// CoreWLAN facts for `ifname` — nil when the interface is not Wi-Fi.
  /// On macOS 14+ ssid/bssid come back nil until the app holds a
  /// Location Services grant; ask once and let the app's periodic
  /// refresh pick the fields up after the user approves.
  private func wifiInfo(for ifname: String?) -> [String: Any]? {
    guard let ifname,
      let w = CWWiFiClient.shared().interface(withName: ifname),
      w.serviceActive()
    else { return nil }
    var m: [String: Any] = [:]
    requestLocationIfNeeded(w)
    m["interfaceName"] = w.interfaceName
    if let ssid = w.ssid() { m["ssid"] = ssid }
    m["ssidAvailable"] = w.ssid() != nil
    if let bssid = w.bssid() { m["bssid"] = bssid }
    m["security"] = securityString(w.security())
    if let detail = securityDetail(w) {
      m["securityDetail"] = detail
    }
    m["rssi"] = w.rssiValue()
    m["noise"] = w.noiseMeasurement()
    m["transmitRate"] = w.transmitRate()
    if let ch = w.wlanChannel() {
      m["channel"] = ch.channelNumber
      m["channelBand"] = channelBandString(ch.channelBand)
      if #available(macOS 10.15, *) {
        m["channelWidth"] = channelWidthString(ch.channelWidth)
      }
    }
    m["phyMode"] = phyModeString(w.activePHYMode())
    if let cc = w.countryCode() { m["countryCode"] = cc }
    if let mac = w.hardwareAddress() { m["mac"] = mac }
    return m
  }

  /// Precise security label parsed from the associated network's scan
  /// record — the private `CWNetwork.scanRecord` accessor returns the
  /// already-parsed beacon IEs, including RSN_IE/WPA_IE dicts with the
  /// AKM suite list + cipher suites that the public CWSecurity enum
  /// flattens into "Personal"/"Enterprise".
  private var securityDetailCache: [String: String] = [:]
  private var lastSecurityScanAt = Date.distantPast

  private func securityDetail(_ w: CWInterface) -> String? {
    let key = w.bssid() ?? w.ssid() ?? w.interfaceName ?? "?"
    let match: (CWNetwork) -> Bool = { net in
      if let b = w.bssid(), let nb = net.bssid { return nb == b }
      return net.ssid == w.ssid()
    }
    if let net = w.cachedScanResults()?.first(where: match),
      let rec = scanRecord(net), let detail = describeSecurity(rec)
    {
      securityDetailCache[key] = detail
      return detail
    }
    if let cached = securityDetailCache[key] { return cached }
    // Scan cache missed — try a real scan, rate-limited so the 2s
    // refresh tick doesn't hammer the radio.
    guard Date().timeIntervalSince(lastSecurityScanAt) > 30 else {
      return nil
    }
    lastSecurityScanAt = Date()
    guard let nets = try? w.scanForNetworks(withSSID: w.ssidData()),
      let net = nets.first(where: match),
      let rec = scanRecord(net), let detail = describeSecurity(rec)
    else { return nil }
    securityDetailCache[key] = detail
    return detail
  }

  private func scanRecord(_ net: CWNetwork) -> [String: Any]? {
    guard net.responds(to: NSSelectorFromString("scanRecord")) else {
      return nil
    }
    return net.value(forKey: "scanRecord") as? [String: Any]
  }

  /// RSN/WPA suite type numbers are the trailing octet of the 00-0F-AC
  /// OUI suite selectors in the beacon IE.
  private func akmName(_ t: Int) -> String {
    switch t {
    case 1: return "802.1X"
    case 2: return "PSK"
    case 3: return "FT-802.1X"
    case 4: return "FT-PSK"
    case 5: return "802.1X-SHA256"
    case 6: return "PSK-SHA256"
    case 7: return "TDLS"
    case 8: return "SAE"
    case 9: return "FT-SAE"
    case 11: return "802.1X-Suite-B"
    case 12: return "802.1X-Suite-B-192"
    case 13: return "FT-802.1X-SHA384"
    case 14: return "FILS-SHA256"
    case 15: return "FILS-SHA384"
    case 16: return "FT-FILS-SHA256"
    case 17: return "FT-FILS-SHA384"
    case 18: return "OWE"
    case 24: return "SAE-EXT"
    default: return "AKM-\(t)"
    }
  }

  private func cipherName(_ t: Int) -> String {
    switch t {
    case 0: return "Group"
    case 1: return "WEP-40"
    case 2: return "TKIP"
    case 4: return "CCMP-128"
    case 5: return "WEP-104"
    case 6: return "BIP-CMAC-128"
    case 7: return "None"
    case 8: return "GCMP-128"
    case 9: return "GCMP-256"
    case 10: return "CCMP-256"
    case 11: return "BIP-GMAC-128"
    case 12: return "BIP-GMAC-256"
    case 13: return "BIP-CMAC-256"
    default: return "Cipher-\(t)"
    }
  }

  private func describeSecurity(_ rec: [String: Any]) -> String? {
    func nums(_ v: Any?) -> [Int] {
      (v as? [NSNumber])?.map { $0.intValue } ?? []
    }
    if let rsn = rec["RSN_IE"] as? [String: Any] {
      let akmTypes = nums(rsn["IE_KEY_RSN_AUTHSELS"])
      let uciphers = nums(rsn["IE_KEY_RSN_UCIPHERS"])
      let mcipher = (rsn["IE_KEY_RSN_MCIPHER"] as? NSNumber)?.intValue
      // WPA3 whenever an SAE-family AKM is present; PSK alongside it
      // means transition mode. A legacy WPA_IE too → WPA mixed mode.
      let sae = akmTypes.contains { [8, 9, 24].contains($0) }
      let psk = akmTypes.contains { [2, 4, 6].contains($0) }
      var gen = sae ? (psk ? "WPA2/WPA3" : "WPA3") : "WPA2"
      if rec["WPA_IE"] != nil { gen = "WPA/" + gen }
      var s = gen
      if !akmTypes.isEmpty {
        s += "-" + akmTypes.map(akmName).joined(separator: "+")
      }
      var extra = uciphers.map(cipherName).joined(separator: "+")
      if let g = mcipher, !uciphers.contains(g) {
        extra += (extra.isEmpty ? "" : ", ") + "group: \(cipherName(g))"
      }
      // RSN capabilities: bit 6 MFPC (PMF capable), bit 7 MFPR (required).
      if let caps = (rsn["IE_KEY_RSN_CAPS"] as? NSNumber)?.intValue {
        if caps & 0x80 != 0 { extra += ", PMF required" }
        else if caps & 0x40 != 0 { extra += ", PMF capable" }
      }
      if !extra.isEmpty { s += " (\(extra))" }
      return s
    }
    if let wpa = rec["WPA_IE"] as? [String: Any] {
      let akms = nums(wpa["IE_KEY_WPA_AUTHSELS"]).map(akmName)
      let uciphers = nums(wpa["IE_KEY_WPA_UCIPHERS"]).map(cipherName)
      var s = "WPA"
      if !akms.isEmpty { s += "-" + akms.joined(separator: "+") }
      if !uciphers.isEmpty {
        s += " (\(uciphers.joined(separator: "+")))"
      }
      return s
    }
    // No security IEs — the beacon capability privacy bit (0x10)
    // distinguishes WEP from a fully open network.
    if let caps = (rec["CAPABILITIES"] as? NSNumber)?.intValue {
      return caps & 0x10 != 0 ? "WEP" : "Open"
    }
    return nil
  }

  private func securityString(_ s: CWSecurity) -> String {
    switch s {
    case .none: return "None"
    case .WEP: return "WEP"
    case .wpaPersonal, .wpaPersonalMixed: return "WPA Personal"
    case .wpa2Personal, .personal: return "WPA2 Personal"
    case .dynamicWEP: return "Dynamic WEP"
    case .wpaEnterprise, .wpaEnterpriseMixed: return "WPA Enterprise"
    case .wpa2Enterprise, .enterprise:
      return "WPA2 Enterprise"
    case .wpa3Personal: return "WPA3 Personal"
    case .wpa3Enterprise: return "WPA3 Enterprise"
    case .wpa3Transition: return "WPA2/WPA3 Transition"
    case .OWE: return "OWE"
    case .oweTransition: return "OWE Transition"
    default: return "Unknown"
    }
  }

  private func phyModeString(_ m: CWPHYMode) -> String {
    switch m {
    case .mode11a: return "802.11a"
    case .mode11b: return "802.11b"
    case .mode11g: return "802.11g"
    case .mode11n: return "802.11n"
    case .mode11ac: return "802.11ac"
    case .mode11ax: return "802.11ax"
    default: return "Unknown"
    }
  }

  private func channelBandString(_ b: CWChannelBand) -> String {
    switch b {
    case .band2GHz: return "2.4 GHz"
    case .band5GHz: return "5 GHz"
    case .band6GHz: return "6 GHz"
    default: return "Unknown"
    }
  }

  @available(macOS 10.15, *)
  private func channelWidthString(_ w: CWChannelWidth) -> String {
    switch w {
    case .width20MHz: return "20 MHz"
    case .width40MHz: return "40 MHz"
    case .width80MHz: return "80 MHz"
    case .width160MHz: return "160 MHz"
    default: return "Unknown"
    }
  }

  /// IPv6 default route (fe80:: link-local gateway, %iface-scoped) —
  /// the AF_INET6 twin of defaultRoute().
  private func defaultGatewayV6() -> String? {
    guard let dump = sysctlDump(op: NET_RT_DUMP, flags: 0, family: AF_INET6)
    else { return nil }
    var gateway: String?
    forEachRouteEntry(in: dump) { rtm, addrs in
      guard gateway == nil,
        (rtm.pointee.rtm_flags & RTF_GATEWAY) != 0,
        let dstOffset = addrs[Int(RTA_DST)],
        let gwOffset = addrs[Int(RTA_GATEWAY)],
        let dstBytes = sockaddrIn6Bytes(in: dump, at: dstOffset),
        dstBytes.allSatisfy({ $0 == 0 }),
        let gwBytes = sockaddrIn6Bytes(in: dump, at: gwOffset)
      else { return }
      gateway = ipv6String(gwBytes, scopeIfname: nil)
    }
    return gateway
  }

  /// Proxy config from the global dynamic-store key — only the scalar
  /// switches/servers the UI can render.
  private func proxySettings(store: SCDynamicStore) -> [String: Any] {
    guard
      let p = SCDynamicStoreCopyValue(
        store, "State:/Network/Global/Proxies" as CFString) as? [String: Any]
    else { return [:] }
    var out: [String: Any] = [:]
    for key in [
      "HTTPEnable", "HTTPProxy", "HTTPPort",
      "HTTPSEnable", "HTTPSProxy", "HTTPSPort",
      "SOCKSEnable", "SOCKSProxy", "SOCKSPort",
      "ProxyAutoConfigEnable", "ProxyAutoConfigURLString",
    ] {
      if let v = p[key], v is String || v is NSNumber { out[key] = v }
    }
    if let ex = p["ExceptionsList"] as? [String] {
      out["exceptions"] = ex
    }
    return out
  }

  /// DHCP lease details for the primary IPv4 service. The lease lives
  /// under State:/Network/Service/<PrimaryService>/DHCP: lease times as
  /// dates plus raw Option_<n> blobs — decoded for the ones the UI can
  /// name (router, server id, lease duration, subnet, DNS, domain).
  private func dhcpInfo(store: SCDynamicStore) -> [String: Any] {
    guard
      let global = SCDynamicStoreCopyValue(
        store, "State:/Network/Global/IPv4" as CFString) as? [String: Any],
      let service = global["PrimaryService"] as? String,
      let dhcp = SCDynamicStoreCopyValue(
        store, "State:/Network/Service/\(service)/DHCP" as CFString)
        as? [String: Any]
    else { return [:] }

    var out: [String: Any] = [:]
    if let d = dhcp["LeaseStartTime"] as? Date {
      out["LeaseStartTime"] = d.timeIntervalSince1970
    }
    if let d = dhcp["LeaseExpirationTime"] as? Date {
      out["LeaseExpirationTime"] = d.timeIntervalSince1970
    }
    if let data = dhcp["Option_54"] as? Data, let ip = ipv4Option(data, at: 0)
    {
      out["ServerIdentifier"] = ip
    }
    if let data = dhcp["Option_51"] as? Data, data.count >= 4 {
      out["LeaseDurationSeconds"] = Int(
        UInt32(bigEndian: data.prefix(4).withUnsafeBytes {
          $0.load(as: UInt32.self)
        }))
    }
    if let data = dhcp["Option_3"] as? Data, let ip = ipv4Option(data, at: 0)
    {
      out["Router"] = ip
    }
    if let data = dhcp["Option_1"] as? Data, let ip = ipv4Option(data, at: 0)
    {
      out["SubnetMask"] = ip
    }
    if let data = dhcp["Option_6"] as? Data, data.count >= 4 {
      var servers: [String] = []
      var i = 0
      while i + 4 <= data.count {
        if let ip = ipv4Option(data, at: i) { servers.append(ip) }
        i += 4
      }
      if !servers.isEmpty { out["DNSServers"] = servers }
    }
    if let data = dhcp["Option_15"] as? Data,
      let domain = String(data: data, encoding: .utf8), !domain.isEmpty
    {
      out["DomainName"] = domain
    }
    return out
  }

  /// Dotted-quad decode of a 4-byte DHCP option blob at `offset`.
  private func ipv4Option(_ data: Data, at offset: Int) -> String? {
    guard offset + 4 <= data.count else { return nil }
    return data[offset..<offset + 4].map(String.init).joined(separator: ".")
  }

  /// System boot time via KERN_BOOTTIME — the "since boot" anchor for
  /// the interface byte counters.
  private func bootTime() -> TimeInterval? {
    var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
    var boot = timeval()
    var size = MemoryLayout<timeval>.size
    guard sysctl(&mib, UInt32(mib.count), &boot, &size, nil, 0) == 0
    else { return nil }
    return TimeInterval(boot.tv_sec) + TimeInterval(boot.tv_usec) / 1_000_000
  }

  /// Walks an IFLIST2 dump; for each if_msghdr2 invokes `body` with the
  /// header and a map of RTA_* index -> byte offset of that sockaddr.
  /// Same record scan as forEachRouteEntry, different header type.
  private func forEachIfEntry(
    in data: Data,
    body: (UnsafePointer<if_msghdr2>, [Int: Int]) -> Void
  ) {
    let headerSize = MemoryLayout<if_msghdr2>.size
    data.withUnsafeBytes { raw in
      guard let base = raw.baseAddress else { return }
      var pos = 0
      while pos + headerSize <= data.count {
        let ifm = base.advanced(by: pos).assumingMemoryBound(
          to: if_msghdr2.self)
        let msglen = Int(ifm.pointee.ifm_msglen)
        if msglen <= 0 { break }

        var addrs: [Int: Int] = [:]
        var saPos = pos + headerSize
        let end = pos + msglen
        var mask = ifm.pointee.ifm_addrs
        var bit = 1
        while mask != 0 && bit <= 0x80 && saPos + 2 <= end {
          if mask & Int32(bit) != 0 {
            addrs[bit] = saPos
            let saLen = Int(
              base.advanced(by: saPos).assumingMemoryBound(to: sockaddr.self)
                .pointee.sa_len)
            saPos += saLen > 0 ? (1 + ((saLen - 1) | 3)) : 4
          }
          mask &= ~Int32(bit)
          bit <<= 1
        }
        body(ifm, addrs)
        pos += msglen
      }
    }
  }

  // MARK: - getArpTable

  /// -> [{"ip","mac","interface"}] — every complete neighbour entry, any iface.
  private func getArpTable() -> [[String: Any]] {
    guard let dump = routeDump(flags: RTF_LLINFO) else { return [] }
    var entries: [[String: Any]] = []

    forEachRouteEntry(in: dump) { rtm, addrs in
      guard let dstOffset = addrs[Int(RTA_DST)],
        let gwOffset = addrs[Int(RTA_GATEWAY)]
      else { return }

      let dst = dump.withUnsafeBytes { raw -> sockaddr_in? in
        raw.baseAddress!.advanced(by: dstOffset)
          .assumingMemoryBound(to: sockaddr.self).pointee.sa_family == UInt8(AF_INET)
          ? raw.baseAddress!.advanced(by: dstOffset)
            .assumingMemoryBound(to: sockaddr_in.self).pointee
          : nil
      }
      guard let dst else { return }
      let ip = String(cString: inet_ntoa(dst.sin_addr))

      guard let sdlBytes = sockaddrDLBytes(in: dump, at: gwOffset),
        let dl = parseSockaddrDL(sdlBytes),
        dl.addr.count == 6
      else { return }

      let mac = dl.addr.map { String(format: "%02x", $0) }.joined(separator: ":")
      // Skip placeholder / broadcast entries.
      if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" { return }
      if ip.hasPrefix("224.") || ip == "255.255.255.255" { return }

      var entry: [String: Any] = ["ip": ip, "mac": mac]
      if !dl.name.isEmpty {
        entry["interface"] = dl.name
      } else if let name = ifName(UInt32(rtm.pointee.rtm_index)) {
        entry["interface"] = name
      }
      entries.append(entry)
    }
    return entries
  }

  // MARK: - getNdpTable

  /// -> [{"ip","mac","interface"}] — complete IPv6 neighbour (NDP)
  /// entries, the IPv6 twin of the ARP table. Same RTF_LLINFO dump,
  /// read with the AF_INET6 MIB.
  private func getNdpTable() -> [[String: Any]] {
    guard let dump = routeDump(flags: RTF_LLINFO, family: AF_INET6) else { return [] }
    var entries: [[String: Any]] = []

    forEachRouteEntry(in: dump) { rtm, addrs in
      guard let dstOffset = addrs[Int(RTA_DST)],
        let gwOffset = addrs[Int(RTA_GATEWAY)]
      else { return }

      guard let addrBytes = sockaddrIn6Bytes(in: dump, at: dstOffset),
        addrBytes[0] != 0xff, // multicast groups are never neighbours
        let ip = ipv6String(addrBytes, scopeIfname: nil),
        ip != "::1"
      else { return }

      guard let sdlBytes = sockaddrDLBytes(in: dump, at: gwOffset),
        let dl = parseSockaddrDL(sdlBytes),
        dl.addr.count == 6
      else { return }

      let mac = dl.addr.map { String(format: "%02x", $0) }.joined(separator: ":")
      if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" { return }

      var entry: [String: Any] = ["ip": ip, "mac": mac]
      if !dl.name.isEmpty {
        entry["interface"] = dl.name
      } else if let name = ifName(UInt32(rtm.pointee.rtm_index)) {
        entry["interface"] = name
      }
      entries.append(entry)
    }
    return entries
  }

  // MARK: - NDP trigger

  /// Sends a few UDP datagrams to the all-nodes multicast (ff02::1) on
  /// `interface`: every IPv6 host that answers (ICMPv6 unreachable)
  /// must first resolve us via NS, landing itself in the neighbour
  /// cache that getNdpTable reads — the IPv6 twin of the IPv4 subnet
  /// UDP blast that feeds the ARP table. Runs off the platform thread.
  private func triggerNdp(interface: String?) {
    guard let interface else { return }
    let scope = if_nametoindex(interface)
    guard scope != 0 else { return }
    DispatchQueue.global().async {
      let fd = socket(AF_INET6, SOCK_DGRAM, 0)
      guard fd >= 0 else { return }
      defer { close(fd) }

      var dst = sockaddr_in6()
      dst.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
      dst.sin6_family = sa_family_t(AF_INET6)
      dst.sin6_port = UInt16(44444).bigEndian
      dst.sin6_scope_id = scope
      withUnsafeMutableBytes(of: &dst.sin6_addr) { a in
        a[0] = 0xff
        a[1] = 0x02
        a[15] = 0x01
      }
      var byte: UInt8 = 0
      withUnsafePointer(to: &dst) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
          for _ in 0..<3 {
            _ = withUnsafeBytes(of: &byte) { b in
              sendto(
                fd, b.baseAddress, 1, 0, sa,
                socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
            usleep(120_000)
          }
        }
      }
    }
  }

  // MARK: - Default route

  private func defaultRoute() -> (gateway: String?, interface: String?) {
    guard let dump = fullRouteDump() else { return (nil, nil) }
    var gateway: String?
    var ifname: String?

    forEachRouteEntry(in: dump) { rtm, addrs in
      guard gateway == nil,
        (rtm.pointee.rtm_flags & RTF_GATEWAY) != 0,
        let dstOffset = addrs[Int(RTA_DST)],
        let gwOffset = addrs[Int(RTA_GATEWAY)]
      else { return }

      let (isDefault, gw) = dump.withUnsafeBytes { raw -> (Bool, in_addr?) in
        let dstSa = raw.baseAddress!.advanced(by: dstOffset)
          .assumingMemoryBound(to: sockaddr.self).pointee
        guard dstSa.sa_family == UInt8(AF_INET) else { return (false, nil) }
        let dst = raw.baseAddress!.advanced(by: dstOffset)
          .assumingMemoryBound(to: sockaddr_in.self).pointee
        let gwSa = raw.baseAddress!.advanced(by: gwOffset)
          .assumingMemoryBound(to: sockaddr.self).pointee
        var gwAddr: in_addr?
        if gwSa.sa_family == UInt8(AF_INET) {
          gwAddr = raw.baseAddress!.advanced(by: gwOffset)
            .assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
        }
        return (dst.sin_addr.s_addr == INADDR_ANY, gwAddr)
      }

      if isDefault, let gw {
        gateway = String(cString: inet_ntoa(gw))
        var nameBuf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        if if_indextoname(UInt32(rtm.pointee.rtm_index), &nameBuf) != nil {
          ifname = String(cString: nameBuf)
        }
      }
    }
    return (gateway, ifname)
  }

  // MARK: - PF_ROUTE sysctl dump

  /// Full routing table (all entries, all flags).
  private func fullRouteDump() -> Data? {
    return sysctlDump(op: NET_RT_DUMP, flags: 0, family: AF_INET)
  }

  /// Neighbour (ARP/NDP LLINFO) table only.
  private func routeDump(flags: Int32, family: Int32 = AF_INET) -> Data? {
    return sysctlDump(op: NET_RT_FLAGS, flags: flags, family: family)
  }

  private func sysctlDump(op: Int32, flags: Int32, family: Int32) -> Data? {
    var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, family, op, flags]
    var needed = 0
    guard sysctl(&mib, UInt32(mib.count), nil, &needed, nil, 0) == 0,
      needed > 0
    else { return nil }
    var buf = [UInt8](repeating: 0, count: needed)
    let status = buf.withUnsafeMutableBytes { raw in
      sysctl(&mib, UInt32(mib.count), raw.baseAddress, &needed, nil, 0)
    }
    guard status == 0 else { return nil }
    return Data(buf[0..<needed])
  }

  /// Walks the dump; for each rt_msghdr2 invokes `body` with the header and a
  /// map of RTA_* index -> byte offset of that sockaddr within the buffer.
  private func forEachRouteEntry(
    in data: Data,
    body: (UnsafePointer<rt_msghdr2>, [Int: Int]) -> Void
  ) {
    let headerSize = MemoryLayout<rt_msghdr2>.size
    data.withUnsafeBytes { raw in
      guard let base = raw.baseAddress else { return }
      var pos = 0
      while pos + headerSize <= data.count {
        let rtm = base.advanced(by: pos).assumingMemoryBound(to: rt_msghdr2.self)
        let msglen = Int(rtm.pointee.rtm_msglen)
        if msglen <= 0 { break }

        var addrs: [Int: Int] = [:]
        var saPos = pos + headerSize
        let end = pos + msglen
        var mask = rtm.pointee.rtm_addrs
        var bit = 1
        while mask != 0 && bit <= 0x80 && saPos + 2 <= end {
          if mask & Int32(bit) != 0 {
            addrs[bit] = saPos
            let saLen = Int(
              base.advanced(by: saPos).assumingMemoryBound(to: sockaddr.self)
                .pointee.sa_len)
            saPos += saLen > 0 ? (1 + ((saLen - 1) | 3)) : 4
          }
          mask &= ~Int32(bit)
          bit <<= 1
        }
        body(rtm, addrs)
        pos += msglen
      }
    }
  }

  // MARK: - sockaddr helpers

  private func ipv4String(from sa: UnsafePointer<sockaddr>) -> String? {
    guard sa.pointee.sa_family == UInt8(AF_INET) else { return nil }
    let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
      $0.pointee.sin_addr
    }
    return String(cString: inet_ntoa(addr))
  }

  private func ifName(_ index: UInt32) -> String? {
    var buf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
    guard if_indextoname(index, &buf) != nil else { return nil }
    return String(cString: buf)
  }

  /// 16 raw address bytes -> canonical IPv6 string. Link-local
  /// addresses (fe80::/10) carry their scope embedded in bytes 2-3 in
  /// the kernel's internal form — strip it and re-attach as `%ifname`
  /// so the result is a usable literal.
  private func ipv6String(_ rawBytes: [UInt8], scopeIfname: String?) -> String? {
    guard rawBytes.count == 16 else { return nil }
    var bytes = rawBytes
    var ifname = scopeIfname
    let linkLocal = bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80
    if linkLocal {
      let embedded = UInt32(bytes[2]) << 8 | UInt32(bytes[3])
      if embedded != 0 {
        bytes[2] = 0
        bytes[3] = 0
        ifname = ifname ?? self.ifName(embedded)
      }
    }
    var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    let ok = bytes.withUnsafeBytes { b in
      inet_ntop(AF_INET6, b.baseAddress, &buf, socklen_t(buf.count)) != nil
    }
    guard ok else { return nil }
    var ip = String(cString: buf)
    if linkLocal, let ifname {
      ip += "%\(ifname)"
    }
    return ip
  }

  /// sin6_addr bytes of the sockaddr_in6 at `offset` in the dump.
  private func sockaddrIn6Bytes(in data: Data, at offset: Int) -> [UInt8]? {
    guard offset + MemoryLayout<sockaddr_in6>.size <= data.count else {
      return nil
    }
    return data.withUnsafeBytes { raw -> [UInt8]? in
      let sa = raw.baseAddress!.advanced(by: offset)
        .assumingMemoryBound(to: sockaddr.self).pointee
      guard sa.sa_family == UInt8(AF_INET6) else { return nil }
      return Array(raw[(offset + 8)..<(offset + 24)])
    }
  }

  private func linkAddress(from sa: UnsafePointer<sockaddr>) -> String? {
    guard sa.pointee.sa_family == UInt8(AF_LINK) else { return nil }
    let bytes = sa.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) {
      dl -> [UInt8] in
      let nlen = Int(dl.pointee.sdl_nlen)
      let alen = Int(dl.pointee.sdl_alen)
      // sdl_data is a fixed 12-byte field holding name + link address; long
      // interface names (e.g. bridge0) leave no room for the MAC.
      guard alen == 6, nlen + alen <= 12 else { return [] }
      return withUnsafeBytes(of: dl.pointee.sdl_data) { raw in
        (nlen..<(nlen + alen)).map { raw[$0] }
      }
    }
    guard bytes.count == 6 else { return nil }
    return bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
  }

  private func sockaddrDLBytes(in data: Data, at offset: Int) -> [UInt8]? {
    guard offset + MemoryLayout<sockaddr_dl>.size <= data.count else {
      return nil
    }
    return data.withUnsafeBytes { raw -> [UInt8]? in
      let sa = raw.baseAddress!.advanced(by: offset)
        .assumingMemoryBound(to: sockaddr.self).pointee
      guard sa.sa_family == UInt8(AF_LINK) else { return nil }
      let len = Int(sa.sa_len)
      guard len >= 8, offset + len <= data.count else { return nil }
      return Array(raw[offset..<(offset + len)])
    }
  }

  /// sockaddr_dl laid out as [header 8B][name nlen][addr alen].
  private func parseSockaddrDL(_ bytes: [UInt8])
    -> (name: String, addr: [UInt8], type: Int)?
  {
    guard bytes.count >= 8 else { return nil }
    let dl = bytes.withUnsafeBytes { raw in
      raw.baseAddress!.assumingMemoryBound(to: sockaddr_dl.self).pointee
    }
    let nlen = Int(dl.sdl_nlen)
    let alen = Int(dl.sdl_alen)
    guard nlen + alen <= bytes.count - 8 else { return nil }
    let nameBytes = bytes[8..<(8 + nlen)]
    let name = String(
      bytes: nameBytes.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
    let addr = Array(bytes[(8 + nlen)..<(8 + nlen + alen)])
    return (name, addr, Int(dl.sdl_type))
  }
}
