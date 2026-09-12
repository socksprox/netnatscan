import Cocoa
import FlutterMacOS
import Darwin

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
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  // MARK: - getNetworkInfo

  /// -> {
  ///   "interfaces": [{"name","ip","netmask","mac"?,"isUp","isLoopback"}],
  ///   "defaultGateway": String?,
  ///   "defaultInterface": String?
  /// }
  private func getNetworkInfo() -> [String: Any] {
    var macByName: [String: String] = [:]
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

    // Attach MACs to IPv4 rows.
    for i in interfaces.indices {
      if let mac = macByName[interfaces[i]["name"] as? String ?? ""] {
        interfaces[i]["mac"] = mac
      }
    }

    let route = defaultRoute()
    return [
      "interfaces": interfaces,
      "defaultGateway": route.gateway ?? NSNull(),
      "defaultInterface": route.interface ?? NSNull(),
    ]
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
      } else {
        var ifname = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        if if_indextoname(UInt32(rtm.pointee.rtm_index), &ifname) != nil {
          entry["interface"] = String(cString: ifname)
        }
      }
      entries.append(entry)
    }
    return entries
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
    return sysctlDump(op: NET_RT_DUMP, flags: 0)
  }

  /// Neighbour (ARP/LLINFO) table only.
  private func routeDump(flags: Int32) -> Data? {
    return sysctlDump(op: NET_RT_FLAGS, flags: flags)
  }

  private func sysctlDump(op: Int32, flags: Int32) -> Data? {
    var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, op, flags]
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
  private func parseSockaddrDL(_ bytes: [UInt8]) -> (name: String, addr: [UInt8])? {
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
    return (name, addr)
  }
}
