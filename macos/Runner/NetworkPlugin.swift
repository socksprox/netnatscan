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
  static let eventsChannelName = "netnatscan/tools_events"

  private let toolEngine = ToolEngine()

  static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(
      name: channelName, binaryMessenger: registrar.messenger)
    let instance = NetworkPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
    let events = FlutterEventChannel(
      name: eventsChannelName, binaryMessenger: registrar.messenger)
    events.setStreamHandler(instance.toolEngine)
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
    case "startPing", "startRoute":
      let args = call.arguments as? [String: Any] ?? [:]
      result(toolEngine.start(call.method, args))
    case "stopTool":
      toolEngine.stop()
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

// MARK: - Tools (ping / route)

/// Ping/route job engine. MethodChannel calls only launch or stop a
/// job; progress streams over the `netnatscan/tools_events`
/// EventChannel as {type: start|reply|timeout|note|hop|hopName|done}
/// maps. Everything runs in-process on BSD sockets:
///  - ICMP ping/probes: SOCK_DGRAM ICMP (the SimplePing mechanism —
///    works inside the App Sandbox, no privileges needed).
///  - UDP ping: connected UDP socket; the host's ICMP port-unreachable
///    comes back as ECONNREFUSED on recv.
///  - TCP ping: nonblocking connect(); ECONNREFUSED also means alive.
///  - Route probes: IP_TTL/IPV6_UNICAST_HOPS per probe; time-exceeded
///    errors are collected on the dgram socket (kernel demuxes errors
///    quoting our echo to it) plus, when available, a raw ICMP socket —
///    required for UDP-probe mode and usually denied by the sandbox.
private final class ToolEngine: NSObject, FlutterStreamHandler {
  private var sink: FlutterEventSink?
  private var job: ToolJob?

  func onListen(
    withArguments arguments: Any?,
    eventSink events: @escaping FlutterEventSink
  ) -> FlutterError? {
    sink = events
    return nil
  }

  func onCancel(withArguments arguments: Any?) -> FlutterError? {
    sink = nil
    return nil
  }

  /// FlutterEventSink isn't thread-safe — hop to the main queue.
  func emit(_ event: [String: Any]) {
    DispatchQueue.main.async { [weak self] in self?.sink?(event) }
  }

  func start(_ method: String, _ args: [String: Any]) -> [String: Any] {
    stop()
    guard
      let host = (args["host"] as? String)?
        .trimmingCharacters(in: .whitespacesAndNewlines),
      !host.isEmpty
    else { return ["ok": false, "message": "Missing target host"] }
    let job: ToolJob =
      method == "startPing"
      ? PingJob(args: args, host: host, engine: self)
      : RouteJob(args: args, host: host, engine: self)
    self.job = job
    job.start()
    return ["ok": true]
  }

  func stop() {
    job?.cancel()
    job = nil
  }
}

/// Socket options that are either absent from the SDK headers or
/// clearer when named after what they do here.
private enum ToolS {
  static let ipTtl: Int32 = 4 // IP_TTL
  static let v6Hops: Int32 = 4 // IPV6_UNICAST_HOPS
  static let ipDontFrag: Int32 = 67 // IP_DONTFRAG
  static let v6DontFrag: Int32 = 61 // IPV6_DONTFRAG
}

private class ToolJob {
  let args: [String: Any]
  let host: String
  let jobId: Int
  weak var engine: ToolEngine?

  private let lock = NSLock()
  private var _cancelled = false
  private var fds: [Int32] = []

  init(args: [String: Any], host: String, engine: ToolEngine) {
    self.args = args
    self.host = host
    self.engine = engine
    self.jobId = (args["job"] as? Int) ?? 0
  }

  var cancelled: Bool {
    lock.lock()
    defer { lock.unlock() }
    return _cancelled
  }

  func track(_ fd: Int32) {
    lock.lock()
    fds.append(fd)
    lock.unlock()
  }

  func untrack(_ fd: Int32) {
    lock.lock()
    fds.removeAll { $0 == fd }
    lock.unlock()
  }

  /// Closing tracked fds unblocks an in-flight poll/recv on the job
  /// queue so stop is near-instant.
  func cancel() {
    lock.lock()
    _cancelled = true
    let open = fds
    fds.removeAll()
    lock.unlock()
    for fd in open { close(fd) }
  }

  func emit(_ event: [String: Any]) {
    var e = event
    e["job"] = jobId
    engine?.emit(e)
  }

  func emitError(_ message: String) {
    emit(["type": "done", "reason": "error", "message": message])
  }

  func start() {
    DispatchQueue.global(qos: .userInitiated).async { [self] in run() }
  }

  func run() {}

  func intArg(_ key: String, _ def: Int) -> Int {
    (args[key] as? Int) ?? def
  }

  // MARK: sockaddr / DNS helpers

  /// getaddrinfo → sockaddr_storage. 'auto' prefers IPv4.
  func resolve(
    _ host: String, family: String, sockType: Int32
  ) -> (sockaddr_storage, socklen_t)? {
    var hints = addrinfo()
    hints.ai_family =
      family == "ipv4" ? AF_INET : family == "ipv6" ? AF_INET6 : AF_UNSPEC
    hints.ai_socktype = sockType
    var res: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res
    else { return nil }
    defer { freeaddrinfo(res) }
    var chosen = first
    if hints.ai_family == AF_UNSPEC {
      var cur: UnsafeMutablePointer<addrinfo>? = first
      while let c = cur {
        if c.pointee.ai_family == AF_INET {
          chosen = c
          break
        }
        cur = c.pointee.ai_next
      }
    }
    var ss = sockaddr_storage()
    memset(&ss, 0, MemoryLayout<sockaddr_storage>.size)
    memcpy(&ss, chosen.pointee.ai_addr, Int(chosen.pointee.ai_addrlen))
    return (ss, chosen.pointee.ai_addrlen)
  }

  /// sockaddr_storage for a numeric IP literal (for reverse DNS).
  func sockaddrFromIp(_ ip: String) -> (sockaddr_storage, socklen_t)? {
    let bare = ip.split(separator: "%").first.map(String.init) ?? ip
    var ss = sockaddr_storage()
    memset(&ss, 0, MemoryLayout<sockaddr_storage>.size)
    if bare.contains(":") {
      let ok = withUnsafeMutablePointer(to: &ss) { p in
        p.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { v6 in
          v6.pointee.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
          v6.pointee.sin6_family = sa_family_t(AF_INET6)
          return inet_pton(AF_INET6, bare, &v6.pointee.sin6_addr) == 1
        }
      }
      return ok ? (ss, socklen_t(MemoryLayout<sockaddr_in6>.size)) : nil
    }
    let ok = withUnsafeMutablePointer(to: &ss) { p in
      p.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { v4 in
        v4.pointee.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        v4.pointee.sin_family = sa_family_t(AF_INET)
        return inet_pton(AF_INET, bare, &v4.pointee.sin_addr) == 1
      }
    }
    return ok ? (ss, socklen_t(MemoryLayout<sockaddr_in>.size)) : nil
  }

  /// getnameinfo(NI_NUMERICHOST) — canonical literal for the address.
  func ipString(_ ss: sockaddr_storage) -> String? {
    var copy = ss
    var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    let r = withUnsafePointer(to: &copy) { p in
      p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
        getnameinfo(
          sa, socklen_t(sa.pointee.sa_len), &buf,
          socklen_t(buf.count), nil, 0, NI_NUMERICHOST)
      }
    }
    return r == 0 ? String(cString: buf) : nil
  }

  /// getnameinfo(NI_NAMEREQD) — reverse DNS; may block on the network,
  /// so callers run it off the job queue.
  func reverseName(_ ss: sockaddr_storage) -> String? {
    var copy = ss
    var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    let r = withUnsafePointer(to: &copy) { p in
      p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
        getnameinfo(
          sa, socklen_t(sa.pointee.sa_len), &buf,
          socklen_t(buf.count), nil, 0, NI_NAMEREQD)
      }
    }
    guard r == 0 else { return nil }
    let name = String(cString: buf)
    return name.isEmpty ? nil : name
  }

  /// Same address, ignoring port — the "is this the target?" test.
  func sameAddr(_ a: sockaddr_storage, _ b: sockaddr_storage) -> Bool {
    guard a.ss_family == b.ss_family else { return false }
    var x = a
    var y = b
    if a.ss_family == sa_family_t(AF_INET) {
      return withUnsafePointer(to: &x) { xp in
        xp.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { xi in
          withUnsafePointer(to: &y) { yp in
            yp.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { yi in
              xi.pointee.sin_addr.s_addr == yi.pointee.sin_addr.s_addr
            }
          }
        }
      }
    }
    return withUnsafePointer(to: &x) { xp in
      xp.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { xi in
        withUnsafePointer(to: &y) { yp in
          yp.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { yi in
            withUnsafeBytes(of: xi.pointee.sin6_addr) { xb in
              withUnsafeBytes(of: yi.pointee.sin6_addr) { yb in
                memcmp(xb.baseAddress, yb.baseAddress, 16) == 0
              }
            }
          }
        }
      }
    }
  }

  func setPort(_ ss: inout sockaddr_storage, _ port: UInt16) {
    if ss.ss_family == sa_family_t(AF_INET) {
      withUnsafeMutablePointer(to: &ss) { p in
        p.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
          $0.pointee.sin_port = port.bigEndian
        }
      }
    } else {
      withUnsafeMutablePointer(to: &ss) { p in
        p.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
          $0.pointee.sin6_port = port.bigEndian
        }
      }
    }
  }

  // MARK: socket I/O

  func setSockOptInt(_ fd: Int32, _ level: Int32, _ name: Int32, _ value: Int32) {
    var v = value
    setsockopt(fd, level, name, &v, socklen_t(MemoryLayout<Int32>.size))
  }

  func sendTo(
    _ fd: Int32, _ bytes: [UInt8],
    _ ss: sockaddr_storage, _ len: socklen_t
  ) -> Int {
    var copy = ss
    return bytes.withUnsafeBufferPointer { buf in
      withUnsafePointer(to: &copy) { p in
        p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
          Darwin.sendto(fd, buf.baseAddress, buf.count, 0, sa, len)
        }
      }
    }
  }

  /// poll() for readability; nil on timeout, error or a closed fd
  /// (cancel surfaces as POLLNVAL, i.e. no POLLIN).
  func pollReadable(_ fds: [Int32], timeoutMs: Int) -> [Int32]? {
    var pfds = fds.map {
      pollfd(fd: $0, events: Int16(POLLIN), revents: 0)
    }
    let r = poll(&pfds, nfds_t(pfds.count), Int32(max(timeoutMs, 0)))
    guard r > 0 else { return nil }
    return (0..<pfds.count).compactMap {
      pfds[$0].revents & Int16(POLLIN) != 0 ? fds[$0] : nil
    }
  }

  struct Incoming {
    var bytes: [UInt8]
    var src: sockaddr_storage
  }

  /// recvfrom() — payload plus the source sockaddr.
  func recvNow(_ fd: Int32) -> Incoming? {
    var buf = [UInt8](repeating: 0, count: 4096)
    var src = sockaddr_storage()
    var srcLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
    let n = buf.withUnsafeMutableBytes { bb in
      withUnsafeMutablePointer(to: &src) { sp in
        sp.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
          recvfrom(fd, bb.baseAddress, bb.count, 0, sa, &srcLen)
        }
      }
    }
    guard n > 0 else { return nil }
    return Incoming(bytes: Array(buf[0..<n]), src: src)
  }

  func soError(_ fd: Int32) -> Int32 {
    var err: Int32 = 0
    var len = socklen_t(MemoryLayout<Int32>.size)
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
    return err
  }

  func errnoString() -> String {
    String(cString: strerror(errno))
  }

  func beep(_ name: String) {
    DispatchQueue.main.async {
      NSSound(named: NSSound.Name(name))?.play()
    }
  }

  // MARK: ICMP packets

  /// ICMP(v6) echo request: 8-byte header + `payload` bytes. The kernel
  /// rewrites the identifier on SOCK_DGRAM sockets (and checksums for
  /// v6), so replies/errors are correlated by sequence number only.
  func buildEcho(seq: Int, v6: Bool, payload: Int) -> [UInt8] {
    let n = 8 + max(payload, 0)
    var pkt = [UInt8](repeating: 0, count: n)
    pkt[0] = v6 ? 128 : 8
    pkt[6] = UInt8((seq >> 8) & 0xff)
    pkt[7] = UInt8(seq & 0xff)
    for i in 8..<n { pkt[i] = UInt8(i & 0xff) }
    if !v6 {
      let c = icmpCksum(pkt)
      pkt[2] = UInt8(c >> 8)
      pkt[3] = UInt8(c & 0xff)
    }
    return pkt
  }

  func icmpCksum(_ bytes: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    var i = 0
    while i + 1 < bytes.count {
      sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
      i += 2
    }
    if i < bytes.count { sum += UInt32(bytes[i]) << 8 }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
    return ~UInt16(truncatingIfNeeded: sum)
  }

  /// Byte offset of the ICMP(v6) message in a received datagram — or
  /// -1 if it doesn't look like IP/ICMP. macOS SOCK_DGRAM ICMP sockets
  /// prepend the IPv4 header (first nibble 4); iOS-style dgram sockets
  /// and IPv6 raw sockets deliver the ICMP message at offset 0.
  func icmpOffset(_ b: [UInt8]) -> Int {
    guard b.count >= 8 else { return -1 }
    switch b[0] >> 4 {
    case 4:
      let ihl = Int(b[0] & 0x0f) * 4
      return ihl >= 20 && b.count > ihl ? ihl : -1
    case 6:
      // Full IPv6 header — only when it actually carries ICMPv6.
      return b.count > 46 && b[6] == 58 ? 40 : -1
    default:
      return 0
    }
  }

  /// Parse an ICMP(v6) message at `bytes[off...]` (see icmpOffset).
  /// Returns (probe index, isEchoReply) — echo replies carry their seq;
  /// errors carry the embedded probe's echo seq, or its UDP dport minus
  /// `udpBasePort` for UDP-probe mode.
  func parseIcmp(
    _ b: [UInt8], off: Int, v6: Bool, udpBasePort: Int?
  ) -> (idx: Int, isReply: Bool)? {
    guard off >= 0, b.count >= off + 8 else { return nil }
    let type = b[off]
    if type == (v6 ? 129 : 0) {
      return (Int(b[off + 6]) << 8 | Int(b[off + 7]), true)
    }
    let isErr = v6 ? (type == 3 || type == 1) : (type == 11 || type == 3)
    guard isErr else { return nil }
    let emb = off + 8
    var idx = -1
    if !v6 {
      guard emb + 28 <= b.count else { return nil }
      let ihl = Int(b[emb] & 0x0f) * 4
      guard ihl >= 20, emb + ihl + 8 <= b.count else { return nil }
      let l4 = emb + ihl
      let proto = b[emb + 9]
      if proto == 1 && b[l4] == 8 {
        idx = Int(b[l4 + 6]) << 8 | Int(b[l4 + 7])
      } else if proto == 17, let base = udpBasePort {
        idx = (Int(b[l4 + 2]) << 8 | Int(b[l4 + 3])) - base
      }
    } else {
      guard emb + 48 <= b.count else { return nil }
      let l4 = emb + 40
      let proto = b[emb + 6]
      if proto == 58 && b[l4] == 128 {
        idx = Int(b[l4 + 6]) << 8 | Int(b[l4 + 7])
      } else if proto == 17, let base = udpBasePort {
        idx = (Int(b[l4 + 2]) << 8 | Int(b[l4 + 3])) - base
      }
    }
    guard idx >= 0 else { return nil }
    return (idx, false)
  }
}

private final class PingJob: ToolJob {
  override func run() {
    let family = args["ipVersion"] as? String ?? "auto"
    let proto = args["protocol"] as? String ?? "icmp"
    let count = intArg("count", 5)
    let interval = intArg("intervalMs", 1000)
    let payload = intArg("payloadBytes", 56)
    let port = intArg("port", proto == "udp" ? 7 : 80)
    let dontFrag = args["dontFragment"] as? Bool ?? false
    let audible = args["audible"] as? Bool ?? false

    guard
      let (dst, dstLen) = resolve(
        host, family: family,
        sockType: proto == "tcp" ? SOCK_STREAM : SOCK_DGRAM)
    else {
      emitError("Could not resolve '\(host)'")
      return
    }
    let v6 = dst.ss_family == sa_family_t(AF_INET6)
    emit([
      "type": "start",
      "tool": "ping",
      "target": host,
      "resolved": ipString(dst) ?? host,
      "detail": args["detail"] as? String ?? "",
    ])

    switch proto {
    case "udp":
      runUdp(
        dst: dst, dstLen: dstLen, v6: v6, count: count,
        interval: interval, port: port, audible: audible)
    case "tcp":
      runTcp(
        dst: dst, dstLen: dstLen, v6: v6, count: count,
        interval: interval, port: port, audible: audible)
    default:
      runIcmp(
        dst: dst, dstLen: dstLen, v6: v6, count: count,
        interval: interval, payload: payload, dontFrag: dontFrag,
        audible: audible)
    }
  }

  private func finishPing(sent: Int, rtts: [Double]) {
    var e: [String: Any] = [
      "type": "done",
      "reason": cancelled ? "stopped" : "finished",
      "sent": sent,
      "received": rtts.count,
      "lossPct": sent > 0
        ? Double(sent - rtts.count) / Double(sent) * 100 : 0.0,
    ]
    if let mn = rtts.min(), let mx = rtts.max(), !rtts.isEmpty {
      e["minMs"] = mn
      e["maxMs"] = mx
      e["avgMs"] = rtts.reduce(0, +) / Double(rtts.count)
    }
    emit(e)
  }

  private func emitReply(
    _ seq: Int, _ from: String, _ rtt: Double,
    _ status: String?, _ audible: Bool
  ) {
    var ev: [String: Any] = [
      "type": "reply",
      "seq": seq,
      "from": from,
      "rttMs": rtt,
    ]
    if let status { ev["status"] = status }
    emit(ev)
    if audible { beep("Ping") }
  }

  /// ICMP echo via SOCK_DGRAM — the kernel picks/rewrites the
  /// identifier, so probes are correlated by seq; each probe waits up
  /// to `interval` ms for a reply, which also sets the probe cadence.
  private func runIcmp(
    dst: sockaddr_storage, dstLen: socklen_t, v6: Bool,
    count: Int, interval: Int, payload: Int,
    dontFrag: Bool, audible: Bool
  ) {
    let fd = socket(
      v6 ? AF_INET6 : AF_INET, SOCK_DGRAM,
      v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP)
    guard fd >= 0 else {
      emitError("ICMP socket failed: \(errnoString())")
      return
    }
    track(fd)
    defer { untrack(fd); close(fd) }

    if dontFrag {
      setSockOptInt(
        fd, v6 ? IPPROTO_IPV6 : IPPROTO_IP,
        v6 ? ToolS.v6DontFrag : ToolS.ipDontFrag, 1)
    }

    var sendTimes = [Int: Date]()
    var rtts = [Double]()
    var sent = 0

    for seq in 0..<count {
      if cancelled { break }
      let pkt = buildEcho(seq: seq, v6: v6, payload: payload)
      let t0 = Date()
      if sendTo(fd, pkt, dst, dstLen) < 0 {
        emit(["type": "note", "message": "send failed: \(errnoString())"])
      }
      sent += 1
      sendTimes[seq] = t0
      let deadline = t0.addingTimeInterval(TimeInterval(interval) / 1000)
      var answered = false
      while !cancelled && !answered {
        let remain = Int(deadline.timeIntervalSinceNow * 1000)
        if remain <= 0 { break }
        guard let ready = pollReadable([fd], timeoutMs: remain),
          !ready.isEmpty, let msg = recvNow(fd)
        else { break }
        guard
          let m = parseIcmp(
            msg.bytes, off: icmpOffset(msg.bytes), v6: v6,
            udpBasePort: nil)
        else { continue }
        switch m {
        case (let s, true):
          // seq-matched echo reply; a late one for an earlier probe
          // still counts (Dart upserts it over the timeout row).
          if let t = sendTimes.removeValue(forKey: s) {
            emitReply(
              s, ipString(msg.src) ?? "",
              Date().timeIntervalSince(t) * 1000, nil, audible)
            rtts.append(Date().timeIntervalSince(t) * 1000)
            if s == seq { answered = true }
          }
        case (let idx, false):
          if sendTimes[idx] != nil {
            emit([
              "type": "note",
              "message": "seq \(idx): destination unreachable",
            ])
          }
        }
      }
      if !answered && !cancelled {
        emit(["type": "timeout", "seq": seq])
        if audible { beep("Funk") }
      }
    }
    finishPing(sent: sent, rtts: rtts)
  }

  /// UDP ping — a datagram to a (usually closed) port; the host's ICMP
  /// port-unreachable lands as ECONNREFUSED on the connected socket.
  /// One fresh socket per probe keeps error delivery clean.
  private func runUdp(
    dst: sockaddr_storage, dstLen: socklen_t, v6: Bool,
    count: Int, interval: Int, port: Int, audible: Bool
  ) {
    var rtts = [Double]()
    var sent = 0
    for seq in 0..<count {
      if cancelled { break }
      let fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0)
      guard fd >= 0 else {
        emitError("UDP socket failed: \(errnoString())")
        return
      }
      track(fd)
      var d = dst
      setPort(&d, UInt16(port))
      let t0 = Date()
      let connected = withUnsafePointer(to: &d) { p in
        p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          connect(fd, $0, dstLen)
        }
      }
      var answered = false
      if connected == 0 {
        var byte: UInt8 = 0
        let n = withUnsafeBytes(of: &byte) { send(fd, $0.baseAddress, 1, 0) }
        if n >= 0 {
          sent += 1
          if let ready = pollReadable([fd], timeoutMs: interval),
            !ready.isEmpty
          {
            var buf = [UInt8](repeating: 0, count: 64)
            let r = recv(fd, &buf, buf.count, 0)
            let rtt = Date().timeIntervalSince(t0) * 1000
            if r > 0 {
              emitReply(seq, ipString(d) ?? "", rtt, "data", audible)
              rtts.append(rtt)
              answered = true
            } else {
              let err = errno
              if err == ECONNREFUSED || soError(fd) == ECONNREFUSED {
                emitReply(
                  seq, ipString(d) ?? "", rtt, "port unreachable", audible)
                rtts.append(rtt)
                answered = true
              }
            }
          }
        }
      } else {
        emit([
          "type": "note",
          "message": "connect failed: \(errnoString())",
        ])
      }
      untrack(fd)
      close(fd)
      if !answered && !cancelled {
        emit(["type": "timeout", "seq": seq])
        if audible { beep("Funk") }
      }
      // Hold the probe cadence for the rest of the interval.
      let rest = interval - Int(Date().timeIntervalSince(t0) * 1000)
      if rest > 0 && !cancelled { usleep(UInt32(rest * 1000)) }
    }
    finishPing(sent: sent, rtts: rtts)
  }

  /// TCP ping — a nonblocking connect(); completing or being refused
  /// both prove the host is up, timeout means filtered/down.
  private func runTcp(
    dst: sockaddr_storage, dstLen: socklen_t, v6: Bool,
    count: Int, interval: Int, port: Int, audible: Bool
  ) {
    var rtts = [Double]()
    var sent = 0
    for seq in 0..<count {
      if cancelled { break }
      let fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0)
      guard fd >= 0 else {
        emitError("TCP socket failed: \(errnoString())")
        return
      }
      track(fd)
      let flags = fcntl(fd, F_GETFL, 0)
      _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
      var d = dst
      setPort(&d, UInt16(port))
      let t0 = Date()
      let cr = withUnsafePointer(to: &d) { p in
        p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          connect(fd, $0, dstLen)
        }
      }
      sent += 1
      var answered = false
      if cr == 0 {
        emitReply(seq, ipString(d) ?? "", 0, "connected", audible)
        rtts.append(0)
        answered = true
      } else if errno == EINPROGRESS {
        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        if poll(&pfd, 1, Int32(interval)) > 0 {
          let err = soError(fd)
          let rtt = Date().timeIntervalSince(t0) * 1000
          if err == 0 {
            emitReply(seq, ipString(d) ?? "", rtt, "connected", audible)
            rtts.append(rtt)
            answered = true
          } else if err == ECONNREFUSED {
            emitReply(seq, ipString(d) ?? "", rtt, "reset", audible)
            rtts.append(rtt)
            answered = true
          }
        }
      } else {
        emit([
          "type": "note",
          "message": "connect failed: \(errnoString())",
        ])
      }
      untrack(fd)
      close(fd)
      if !answered && !cancelled {
        emit(["type": "timeout", "seq": seq])
        if audible { beep("Funk") }
      }
      let rest = interval - Int(Date().timeIntervalSince(t0) * 1000)
      if rest > 0 && !cancelled { usleep(UInt32(rest * 1000)) }
    }
    finishPing(sent: sent, rtts: rtts)
  }
}

private final class RouteJob: ToolJob {
  private let udpBasePort = 33434
  private var hopResults = [Int: [[String: Any]?]]()
  private var nameCache = [String: String]()

  override func run() {
    let family = args["ipVersion"] as? String ?? "auto"
    var udp = args["udpProbes"] as? Bool ?? false
    let maxHops = intArg("maxHops", 30)
    let pph = intArg("probesPerHop", 3)
    let maxDelay = intArg("maxDelayMs", 2000)
    let minDelay = intArg("minDelayMs", 100)

    guard
      let (dst, dstLen) = resolve(host, family: family, sockType: SOCK_DGRAM)
    else {
      emitError("Could not resolve '\(host)'")
      return
    }
    let v6 = dst.ss_family == sa_family_t(AF_INET6)
    let resolvedIp = ipString(dst) ?? host

    // Receivers: the dgram ICMP socket doubles as the sender in ICMP
    // mode and still gets errors quoting our echoes; the raw socket is
    // required to see errors quoting UDP probes (usually denied by the
    // sandbox — degrading to ICMP keeps the tool working).
    let icmpFd = socket(
      v6 ? AF_INET6 : AF_INET, SOCK_DGRAM,
      v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP)
    let rawFd = socket(
      v6 ? AF_INET6 : AF_INET, SOCK_RAW,
      v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP)
    var udpFd: Int32 = -1
    if udp {
      if rawFd < 0 {
        emit([
          "type": "note",
          "message":
            "UDP probes need raw sockets (blocked by the sandbox) — using ICMP",
        ])
        udp = false
      } else {
        udpFd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0)
        if udpFd < 0 {
          emit(["type": "note", "message": "UDP socket failed — using ICMP"])
          udp = false
        }
      }
    }
    guard icmpFd >= 0 else {
      emitError("ICMP socket failed: \(errnoString())")
      if rawFd >= 0 { close(rawFd) }
      return
    }
    track(icmpFd)
    if rawFd >= 0 { track(rawFd) }
    if udpFd >= 0 { track(udpFd) }
    defer {
      untrack(icmpFd)
      close(icmpFd)
      if rawFd >= 0 {
        untrack(rawFd)
        close(rawFd)
      }
      if udpFd >= 0 {
        untrack(udpFd)
        close(udpFd)
      }
    }

    emit([
      "type": "start",
      "tool": "route",
      "target": host,
      "resolved": resolvedIp,
      "detail": args["detail"] as? String ?? "",
    ])

    var sendTimes = [Int: Date]()
    var answered = Set<Int>()
    var reached = false
    var sendFailed = false
    var hopsDone = 0
    let recvFds = udp ? [rawFd] : [icmpFd, rawFd].filter { $0 >= 0 }

    for hop in 1...maxHops {
      if cancelled || reached { break }
      var lastSend = Date.distantPast
      for p in 0..<pph {
        if cancelled { break }
        let idx = (hop - 1) * pph + p
        if udp {
          setSockOptInt(
            udpFd, v6 ? IPPROTO_IPV6 : IPPROTO_IP,
            v6 ? ToolS.v6Hops : ToolS.ipTtl, Int32(hop))
          var d = dst
          setPort(&d, UInt16(udpBasePort + idx))
          if sendTo(
            udpFd, [UInt8](repeating: 0x61, count: 24), d, dstLen) < 0
            && !sendFailed
          {
            sendFailed = true
            emit([
              "type": "note",
              "message": "UDP probe send failed: \(errnoString())",
            ])
          }
        } else {
          setSockOptInt(
            icmpFd, v6 ? IPPROTO_IPV6 : IPPROTO_IP,
            v6 ? ToolS.v6Hops : ToolS.ipTtl, Int32(hop))
          if sendTo(
            icmpFd, buildEcho(seq: idx, v6: v6, payload: 24), dst, dstLen)
            < 0 && !sendFailed
          {
            sendFailed = true
            emit([
              "type": "note",
              "message": "ICMP probe send failed: \(errnoString())",
            ])
          }
        }
        sendTimes[idx] = Date()
        lastSend = Date()
        if minDelay > 0 && p + 1 < pph {
          usleep(UInt32(minDelay * 1000))
        }
      }

      // Collect replies until every probe of this hop is answered or
      // maxDelay after the last send; late answers for earlier hops
      // re-emit that hop via handleMatch.
      let deadline = lastSend.addingTimeInterval(
        TimeInterval(maxDelay) / 1000)
      while !cancelled {
        let remain = Int(deadline.timeIntervalSinceNow * 1000)
        if remain <= 0 { break }
        guard let ready = pollReadable(recvFds, timeoutMs: remain),
          !ready.isEmpty
        else { break }
        for fd in ready {
          guard let msg = recvNow(fd) else { continue }
          guard
            let m = parseIcmp(
              msg.bytes, off: icmpOffset(msg.bytes), v6: v6,
              udpBasePort: udp ? udpBasePort : nil)
          else { continue }
          handleMatch(
            m, src: msg.src, dst: dst, pph: pph,
            sendTimes: sendTimes, answered: &answered,
            reached: &reached, currentHop: hop)
        }
      }

      emitHop(hop)
      hopsDone = hop
      resolveHopNames(hop)
    }

    emit([
      "type": "done",
      "reason": cancelled ? "stopped" : "finished",
      "hops": hopsDone,
      "reached": reached,
    ])
  }

  /// Match a parsed ICMP message to a pending probe and record the
  /// (ip, rtt) hit into hopResults. Reached = the answer came from the
  /// target itself (echo reply or unreachable from the destination).
  private func handleMatch(
    _ m: (idx: Int, isReply: Bool), src: sockaddr_storage,
    dst: sockaddr_storage, pph: Int, sendTimes: [Int: Date],
    answered: inout Set<Int>, reached: inout Bool, currentHop: Int
  ) {
    let idx = m.idx
    guard idx >= 0, !answered.contains(idx), let t = sendTimes[idx]
    else { return }
    answered.insert(idx)
    let rtt = Date().timeIntervalSince(t) * 1000
    let ip = ipString(src) ?? ""
    let hop = idx / pph + 1
    let p = idx % pph
    var arr = hopResults[hop] ?? [[String: Any]?](repeating: nil, count: pph)
    arr[p] = ["ip": ip, "rttMs": rtt]
    hopResults[hop] = arr
    if hop != currentHop {
      emitHop(hop)
      resolveHopNames(hop)
    }
    if sameAddr(src, dst) { reached = true }
  }

  private func emitHop(_ hop: Int) {
    let probes = (hopResults[hop] ?? []).map { p -> [String: Any] in
      guard let p else { return ["ip": NSNull(), "rttMs": NSNull()] }
      return p
    }
    emit(["type": "hop", "hop": hop, "probes": probes])
  }

  /// Reverse-DNS each hop IP on a background queue; a hit lands as a
  /// hopName event the UI merges into the hop row.
  private func resolveHopNames(_ hop: Int) {
    guard let probes = hopResults[hop] else { return }
    for pr in probes {
      guard let ip = pr?["ip"] as? String, nameCache[ip] == nil
      else { continue }
      nameCache[ip] = ""
      DispatchQueue.global().async { [weak self] in
        guard let self, !self.cancelled,
          let (ss, _) = self.sockaddrFromIp(ip),
          let name = self.reverseName(ss)
        else { return }
        self.emit([
          "type": "hopName", "hop": hop, "ip": ip, "hostname": name,
        ])
      }
    }
  }
}
