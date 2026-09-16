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
    case "getNdpTable":
      result(getNdpTable())
    case "triggerNdp":
      triggerNdp(interface: call.arguments as? String)
      result(nil)
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
