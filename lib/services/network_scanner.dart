import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../models/network_device.dart';
import 'mdns_discovery.dart';
import 'name_cache.dart';
import 'oui_db.dart';

/// One local network interface as reported by the macOS side.
class InterfaceInfo {
  final String name;
  final String ip;
  final String? netmask;
  final String? mac;
  final bool isUp;
  final bool isLoopback;

  InterfaceInfo({
    required this.name,
    required this.ip,
    this.netmask,
    this.mac,
    this.isUp = false,
    this.isLoopback = false,
  });

  factory InterfaceInfo.fromMap(Map<dynamic, dynamic> m) => InterfaceInfo(
    name: m['name'] as String,
    ip: m['ip'] as String,
    netmask: m['netmask'] as String?,
    mac: m['mac'] as String?,
    isUp: m['isUp'] as bool? ?? false,
    isLoopback: m['isLoopback'] as bool? ?? false,
  );

  /// IPv4 subnet in CIDR notation, e.g. `192.168.1.0/24`.
  String? get cidr {
    final mask = netmask;
    if (mask == null) return null;
    final prefix = _maskToPrefix(mask);
    if (prefix == null) return null;
    final net = _toInt(ip) & _toInt(mask);
    return '${_fromInt(net)}/$prefix';
  }

  static int? _maskToPrefix(String mask) {
    final v = _toInt(mask);
    var prefix = 0;
    var seenZero = false;
    for (var i = 31; i >= 0; i--) {
      final bit = (v >> i) & 1;
      if (bit == 1 && seenZero) return null; // non-contiguous mask
      if (bit == 1) {
        prefix++;
      } else {
        seenZero = true;
      }
    }
    return prefix;
  }

  static int _toInt(String ip) {
    final p = ip.split('.').map(int.parse).toList();
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
  }

  static String _fromInt(int v) =>
      '${(v >> 24) & 255}.${(v >> 16) & 255}.${(v >> 8) & 255}.${v & 255}';
}

class NetworkInfo {
  final List<InterfaceInfo> interfaces;
  final String? defaultGateway;
  final String? defaultInterface;

  NetworkInfo({
    required this.interfaces,
    this.defaultGateway,
    this.defaultInterface,
  });

  /// The interface carrying the default route, else the first up, non-loopback
  /// IPv4 interface.
  InterfaceInfo? get primary {
    if (defaultInterface != null) {
      for (final i in interfaces) {
        if (i.name == defaultInterface && i.isUp && !i.isLoopback) return i;
      }
    }
    for (final i in interfaces) {
      if (i.isUp && !i.isLoopback) return i;
    }
    return null;
  }
}

enum ScanPhase { idle, probing, resolving, done, failed }

class ScanProgress {
  final ScanPhase phase;
  final int done;
  final int total;
  final String label;

  ScanProgress(this.phase, this.done, this.total, this.label);

  double get fraction => total <= 0 ? 0 : done / total;
}

/// Drives a LAN device scan:
///
/// 1. Ask the native side for interfaces + default route.
/// 2. Blast a UDP datagram at every host address in the subnet — any
///    outbound L2 packet forces the kernel to ARP, and every live host on
///    the link must answer ARP to be reachable at all.
/// 3. Read the kernel ARP table: complete entries inside the subnet are
///    live devices with real MAC addresses.
/// 4. Enrich: OUI vendor, reverse-DNS hostname, TCP connect latency.
class NetworkScanner extends ChangeNotifier {
  static const _channel = MethodChannel('netnatscan/network');
  static const _maxHosts = 4096; // cap the sweep, /16 subnets get truncated

  NetworkInfo? network;
  List<NetworkDevice> devices = [];
  ScanProgress progress = ScanProgress(ScanPhase.idle, 0, 0, '');
  String? error;
  String? scanNote;
  DateTime? lastScanAt;

  bool get scanning =>
      progress.phase == ScanPhase.probing ||
      progress.phase == ScanPhase.resolving;

  Future<void> refreshNetworkInfo() async {
    try {
      final res = await _channel.invokeMapMethod<String, dynamic>(
        'getNetworkInfo',
      );
      final ifaces =
          (res?['interfaces'] as List?)
              ?.map((e) => InterfaceInfo.fromMap(e as Map))
              .toList() ??
          [];
      network = NetworkInfo(
        interfaces: ifaces,
        defaultGateway: res?['defaultGateway'] as String?,
        defaultInterface: res?['defaultInterface'] as String?,
      );
      error = null;
    } catch (e) {
      error = 'Could not read network interfaces: $e';
    }
    notifyListeners();
  }

  List<String> _subnetHosts(InterfaceInfo iface) {
    final cidr = iface.cidr;
    if (cidr == null) return [iface.ip];
    final prefix = int.parse(cidr.split('/').last);
    final hostBits = 32 - prefix;
    final count = (1 << hostBits) - 2; // exclude network + broadcast
    if (count <= 0) return [iface.ip];
    final net =
        InterfaceInfo._toInt(iface.ip) & InterfaceInfo._toInt(iface.netmask!);
    final limit = count > _maxHosts ? _maxHosts : count;
    return List.generate(limit, (i) => InterfaceInfo._fromInt(net + 1 + i));
  }

  Future<void> scan() async {
    if (scanning) return;
    await OuiDb.instance.load();
    await DeviceNameCache.instance.load();
    if (network == null) await refreshNetworkInfo();

    final iface = network?.primary;
    if (iface == null) {
      error = 'No active network interface found';
      progress = ScanProgress(ScanPhase.failed, 0, 0, '');
      notifyListeners();
      return;
    }

    final hosts = _subnetHosts(iface);
    scanNote = hosts.length < _hostCount(iface)
        ? 'Large subnet — scanning first ${hosts.length} addresses'
        : null;

    devices = [];
    error = null;
    progress = ScanProgress(
      ScanPhase.probing,
      0,
      hosts.length,
      'Probing ${iface.cidr ?? iface.ip}',
    );
    notifyListeners();

    // --- Phase 1: trigger ARP for every host, then read the table. ---
    RawDatagramSocket? socket;
    try {
      socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      socket.broadcastEnabled = true;
      final payload = Uint8List.fromList([0]);

      // Three passes over the subnet, ~300ms apart, then a short settle
      // window so late ARP replies land in the kernel table.
      for (var pass = 0; pass < 3; pass++) {
        for (var i = 0; i < hosts.length; i++) {
          socket.send(payload, InternetAddress(hosts[i]), 44444);
          if (i % 128 == 0) {
            progress = ScanProgress(
              ScanPhase.probing,
              i,
              hosts.length,
              'Probing ${iface.cidr ?? iface.ip}',
            );
            notifyListeners();
            await Future.delayed(const Duration(milliseconds: 8));
          }
        }
        if (pass < 2) await Future.delayed(const Duration(milliseconds: 300));
      }
      await Future.delayed(const Duration(milliseconds: 600));
    } catch (e) {
      error = 'Network probe failed: $e';
      progress = ScanProgress(ScanPhase.failed, 0, 0, '');
      notifyListeners();
      socket?.close();
      return;
    } finally {
      socket?.close();
    }

    // --- Phase 2: ARP table -> devices. ---
    List<Map<dynamic, dynamic>> arpRows;
    try {
      final res = await _channel.invokeListMethod<Map<dynamic, dynamic>>(
        'getArpTable',
      );
      arpRows = res ?? [];
    } catch (e) {
      error = 'Could not read ARP table: $e';
      progress = ScanProgress(ScanPhase.failed, 0, 0, '');
      notifyListeners();
      return;
    }

    final hostSet = hosts.toSet();
    final seen = <String>{};
    final found = <NetworkDevice>[];
    for (final row in arpRows) {
      final ip = row['ip'] as String?;
      final mac = row['mac'] as String?;
      if (ip == null || mac == null || !hostSet.contains(ip)) continue;
      if (!seen.add(ip)) continue;
      found.add(
        NetworkDevice(
          ip: ip,
          mac: mac,
          vendor: OuiDb.instance.lookup(mac),
          isSelf: ip == iface.ip,
          isGateway: ip == network?.defaultGateway,
          respondedToProbe: true,
        ),
      );
    }
    // The host itself never appears in its own ARP table.
    if (!seen.contains(iface.ip)) {
      found.add(
        NetworkDevice(
          ip: iface.ip,
          mac: iface.mac,
          vendor: OuiDb.instance.lookup(iface.mac),
          hostname: Platform.localHostname.replaceAll(RegExp(r'\.local$'), ''),
          isSelf: true,
          respondedToProbe: true,
        ),
      );
    }
    for (final d in found) {
      if (d.isSelf && (d.hostname == null || d.hostname!.isEmpty)) {
        d.hostname = Platform.localHostname.replaceAll(RegExp(r'\.local$'), '');
      }
      if (d.isSelf) d.nameSource = DeviceNameSource.local;
    }
    found.sort(
      (a, b) =>
          InterfaceInfo._toInt(a.ip).compareTo(InterfaceInfo._toInt(b.ip)),
    );
    devices = found;
    debugPrint(
      'netnatscan: ARP scan found ${found.length} devices on ${iface.cidr ?? iface.ip}',
    );
    notifyListeners();

    // --- Phase 3: enrichment (mDNS names + PTR + latency), best-effort. ---
    progress = ScanProgress(
      ScanPhase.resolving,
      0,
      devices.length,
      'Resolving names',
    );
    notifyListeners();
    final mdnsFuture = _discoverMdns();
    var resolved = 0;
    await _pool(devices, 24, (d) async {
      await Future.wait([_resolveName(d), _probeLatency(d)]);
      resolved++;
      if (resolved % 4 == 0 || resolved == devices.length) {
        progress = ScanProgress(
          ScanPhase.resolving,
          resolved,
          devices.length,
          'Resolving names',
        );
        notifyListeners();
      }
    });
    await mdnsFuture;
    await _applyNameCache();
    _startPassiveMdns();

    for (final d in devices) {
      debugPrint(
        'netnatscan: ${d.ip}\t${d.displayName}\t${d.vendor ?? '-'}\t${d.typeLabel}',
      );
    }
    devices = [...devices];
    progress = ScanProgress(ScanPhase.done, 1, 1, '');
    lastScanAt = DateTime.now();
    notifyListeners();
  }

  /// Bonjour service types worth browsing, mapped to the device class they
  /// most strongly imply. Browsing also yields the pretty instance name —
  /// the only name devices with private MACs (iPhones) actually broadcast.
  static const _mdnsServiceTypes = [
    '_companion-link._tcp',
    '_remotepairing._tcp',
    '_apple-mobdev2._tcp',
    '_airplay._tcp',
    '_raop._tcp',
    '_hap._tcp',
    '_homekit._tcp',
    '_ipp._tcp',
    '_ipps._tcp',
    '_printer._tcp',
    '_pdl-datastream._tcp',
    '_googlecast._tcp',
    '_sonos._tcp',
    '_spotify-connect._tcp',
    '_smb._tcp',
    '_afpovertcp._tcp',
    '_device-info._tcp',
    '_workstation._tcp',
    '_ssh._tcp',
    '_sleep-proxy._udp',
    '_matter._tcp',
    '_esphome._tcp',
    '_nvstream_dbd._tcp',
    '_adisk._tcp',
  ];

  Future<void> _discoverMdns() async {
    try {
      final result = await MdnsDiscovery.browse(
        types: _mdnsServiceTypes,
        timeout: const Duration(milliseconds: 4000),
        targets: [for (final d in devices) d.ip],
      );
      debugPrint(
        'netnatscan mdns: ${result.services.length} services, '
        '${result.ptrNames.length + result.hostNames.length} hostnames',
      );
      _applyMdnsResult(result);
    } catch (e) {
      debugPrint('netnatscan: mDNS discovery failed: $e');
    }
  }

  /// Maps a browse result onto the device list: names, service types, and
  /// the full service records shown in the detail view. Prefer IPs proven
  /// by SRV→A resolution — devices mirror each other's PTRs, so the packet
  /// source alone can misattribute services (and names).
  void _applyMdnsResult(MdnsResult result) {
    final byIp = {for (final d in devices) d.ip: d};

    // Collect every name hint per device with its provenance, then pick
    // the best one rather than the first to arrive: a device's own
    // hostname (reverse-PTR) outweighs service-level names, cryptic
    // blobs lose to anything readable, and short wins ties — a TV shows
    // "Vee tv" instead of its googlecast UUID.
    final candidates =
        <String, List<(String, int, DeviceNameSource, String?)>>{};
    void addCandidate(
      String ip,
      String? name,
      int weight,
      DeviceNameSource src, [
      String? detail,
    ]) {
      if (name == null || name.isEmpty) return;
      candidates.putIfAbsent(ip, () => []).add((name, weight, src, detail));
    }

    for (final e in result.ptrNames.entries) {
      addCandidate(e.key, e.value, 40, DeviceNameSource.mdnsPtr);
    }
    for (final svc in result.services) {
      final type = svc.type
          .toLowerCase()
          .replaceAll(RegExp(r'\.$'), '')
          .replaceAll(RegExp(r'\._(tcp|udp)$'), '');
      // The SRV host only names the addresses its A/AAAA records prove.
      if (svc.host != null) {
        final host = svc.host!.replaceAll(RegExp(r'\.local$'), '');
        for (final ip in svc.resolvedIps) {
          addCandidate(ip, host, 30, DeviceNameSource.mdnsHost, type);
        }
      }
      final ips = svc.resolvedIps.isNotEmpty ? svc.resolvedIps : svc.ips;
      for (final ip in ips) {
        addCandidate(ip, svc.name, 30, DeviceNameSource.mdnsInstance, type);
        final d = byIp[ip];
        if (d == null) continue;
        if (type.isNotEmpty) d.mdnsTypes.add(type);
        d.mdnsServices.removeWhere(
          (s) => s.name == svc.name && s.type == svc.type,
        );
        d.mdnsServices.add(svc);
        d.isStandby = false;
        d.lastSeenAt = DateTime.now();
      }
    }
    for (final e in candidates.entries) {
      final d = byIp[e.key];
      if (d == null) continue;
      e.value.sort(
        (a, b) => _nameScore(b).compareTo(_nameScore(a)) != 0
            ? _nameScore(b).compareTo(_nameScore(a))
            : a.$1.length.compareTo(b.$1.length),
      );
      final best = e.value.first;
      d.mdnsName = best.$1;
      d.nameSource = best.$3;
      d.nameSourceDetail = best.$4;
      d.seenNames.addAll(e.value.map((c) => c.$1));
      d.seenNames.remove(best.$1);
      d.hostname ??= d.mdnsName;
      d.isStandby = false;
      d.lastSeenAt = DateTime.now();
    }
    notifyListeners();
  }

  int _nameScore((String, int, DeviceNameSource, String?) c) =>
      c.$2 - (_crypticName.hasMatch(c.$1) ? 25 : 0);

  /// Service/host names that are identifiers, not labels: UUIDs, MACs,
  /// '@'-suffixed ids, and long hex runs ("96005366-8df3-…", "b6:6c:…@",
  /// "B36ACBEE-…"). Readable names don't match any of these.
  static final _crypticName = RegExp(
    r'@'
    r'|([0-9a-fA-F]{2}[:-]){3,}'
    r'|[0-9a-fA-F]{16,}'
    r'|[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',
  );

  bool _passiveMdnsRunning = false;
  bool _disposed = false;

  /// Long-lived background browse: keeps the 5353 socket open and re-asks
  /// silent devices once per cycle. Nothing can wake a sleeping phone
  /// remotely — but when it surfaces on its own for maintenance, this
  /// catches the announcement or answer within a minute and restores its
  /// live identity instead of the cached standby one.
  void _startPassiveMdns() {
    if (_passiveMdnsRunning) return;
    _passiveMdnsRunning = true;
    () async {
      while (!_disposed) {
        try {
          final result = await MdnsDiscovery.browse(
            types: _mdnsServiceTypes,
            timeout: const Duration(seconds: 45),
            targets: [
              for (final d in devices)
                if (d.mdnsTypes.isEmpty) d.ip,
            ],
          );
          if (_disposed) return;
          _applyMdnsResult(result);
          await _applyNameCache();
        } catch (_) {}
        if (!_disposed) await Future.delayed(const Duration(seconds: 5));
      }
    }();
  }

  /// One-shot re-probe of a single device from the detail view: unicast
  /// mDNS straight at it, in case it woke since the last scan. Returns
  /// true only if this device answered the query just now — a stale
  /// `lastSeenAt` doesn't count.
  Future<bool> probeDevice(NetworkDevice d) async {
    final start = DateTime.now();
    try {
      final result = await MdnsDiscovery.browse(
        types: _mdnsServiceTypes,
        timeout: const Duration(milliseconds: 2500),
        targets: [d.ip],
      );
      _applyMdnsResult(result);
      await _applyNameCache();
    } catch (_) {}
    final seen = d.lastSeenAt;
    return seen != null && seen.isAfter(start);
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }

  /// Phones in standby keep their ARP entry alive via the Wi-Fi chip but
  /// stop answering Bonjour — they show up silent. When a device gave us
  /// no fresh identity evidence, restore its identity from the persistent
  /// MAC-keyed cache and flag it as standby; when it did answer, refresh
  /// the cache so the next silent scan still knows its name.
  ///
  /// "Live" = `lastSeenAt` is recent — set only by real answers (mDNS,
  /// PTR, TLS). Deriving it from retained fields like `mdnsTypes` would
  /// keep a once-answered device "live" forever across passive cycles.
  Future<void> _applyNameCache() async {
    final cache = DeviceNameCache.instance;
    final now = DateTime.now();
    for (final d in devices) {
      final mac = d.mac;
      if (mac == null) continue;
      final live =
          d.isSelf ||
          (d.lastSeenAt != null &&
              now.difference(d.lastSeenAt!) < const Duration(minutes: 1));
      if (live) {
        d.isStandby = false;
        final name = d.mdnsName ?? d.hostname;
        if (name != null && name.isNotEmpty) {
          cache.update(mac, name, d.mdnsTypes, seen: d.lastSeenAt);
        }
      } else {
        final cached = cache.lookup(mac);
        if (cached != null) {
          d.mdnsName = cached.name;
          d.nameSource = DeviceNameSource.cache;
          d.nameSourceDetail = null;
          d.mdnsTypes.addAll(cached.mdnsTypes);
          d.isStandby = true;
          d.lastSeenAt = cached.lastSeen;
        }
      }
    }
    await cache.save();
  }

  Future<void> _resolveName(NetworkDevice d) async {
    try {
      final addr = await InternetAddress(
        d.ip,
      ).reverse().timeout(const Duration(milliseconds: 1200));
      var host = addr.host;
      if (host.endsWith('.')) host = host.substring(0, host.length - 1);
      if (host != d.ip && host.isNotEmpty) {
        d.hostname = host.replaceAll(RegExp(r'\.local$'), '');
        if (d.mdnsName == null) d.nameSource = DeviceNameSource.dns;
        d.lastSeenAt = DateTime.now(); // fresh PTR identity evidence
      }
    } catch (_) {}
  }

  /// TCP connect gives us an RTT without raw sockets: both a completed
  /// handshake and a refused connection prove the host is alive and time
  /// it. When 443 answers we take the free TLS cert too — one handshake
  /// on an already-open port, not a scan.
  Future<void> _probeLatency(NetworkDevice d) async {
    const ports = [443, 80, 22];
    for (final port in ports) {
      final sw = Stopwatch()..start();
      try {
        final s = await Socket.connect(
          d.ip,
          port,
          timeout: const Duration(milliseconds: 400),
        );
        s.destroy();
        d.openPorts.add(port);
        d.rttMs = sw.elapsedMilliseconds;
        if (port == 443) await _probeTls(d);
        return;
      } on SocketException catch (e) {
        sw.stop();
        if (e.osError?.errorCode == 61 || // ECONNREFUSED
            e.osError?.errorCode == 54) {
          // ECONNRESET
          d.rttMs = sw.elapsedMilliseconds;
          return;
        }
      } catch (_) {}
    }
  }

  /// TCP ports worth checking on an explicit per-device scan, grouped by
  /// what they reveal — remote access, file sharing, printers, cameras,
  /// media, IoT, admin panels. `commonScanPorts` probes in ~1s;
  /// `extendedScanPorts` adds the rarer-but-diagnostic services.
  static const commonScanPorts = [
    22,
    23,
    53,
    80,
    443,
    445,
    548,
    554,
    631,
    1883,
    5000,
    5060,
    7000,
    8008,
    8009,
    8080,
    8443,
    9100,
    32400,
    62078,
  ];
  static const extendedScanPorts = [
    ...commonScanPorts,
    21,
    25,
    110,
    139,
    143,
    515,
    873,
    993,
    995,
    1723,
    2049,
    3000,
    3128,
    3306,
    3389,
    3689,
    5357,
    5432,
    5900,
    5985,
    6379,
    7547,
    8000,
    8291,
    8883,
    8888,
    27017,
  ];

  /// Well-known service labels for the ports above.
  static const portServices = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    515: 'LPD',
    548: 'AFP',
    554: 'RTSP',
    631: 'IPP',
    873: 'rsync',
    993: 'IMAPS',
    995: 'POP3S',
    1723: 'PPTP',
    1883: 'MQTT',
    2049: 'NFS',
    3000: 'dev HTTP',
    3128: 'proxy',
    3306: 'MySQL',
    3389: 'RDP',
    3689: 'DAAP',
    5000: 'UPnP',
    5060: 'SIP',
    5357: 'WSD',
    5432: 'PostgreSQL',
    5900: 'VNC',
    5985: 'WinRM',
    6379: 'Redis',
    7000: 'AirPlay',
    7547: 'TR-069',
    8000: 'HTTP alt',
    8008: 'Chromecast',
    8009: 'Chromecast TLS',
    8080: 'HTTP alt',
    8443: 'HTTPS alt',
    8883: 'MQTTS',
    8888: 'HTTP alt',
    9100: 'JetDirect',
    27017: 'MongoDB',
    32400: 'Plex',
    62078: 'iOS sync',
    8291: 'Winbox',
  };

  /// Explicit per-device port scan (from the device menu / detail view) —
  /// probes [ports] in 8-wide parallel chunks, re-verifies every port in
  /// the set, and grabs the TLS cert if an HTTPS port answers.
  Future<void> scanPorts(NetworkDevice d, List<int> ports) async {
    final list =
        (ports.toSet()..removeWhere((p) => p <= 0 || p > 65535)).toList()
          ..sort();
    d.openPorts.removeAll(list.toSet());
    for (var i = 0; i < list.length; i += 8) {
      await Future.wait(
        list.skip(i).take(8).map((port) async {
          final sw = Stopwatch()..start();
          try {
            final s = await Socket.connect(
              d.ip,
              port,
              timeout: const Duration(milliseconds: 500),
            );
            s.destroy();
            d.openPorts.add(port);
            d.rttMs ??= sw.elapsedMilliseconds;
          } on SocketException catch (e) {
            sw.stop();
            if (e.osError?.errorCode == 61 || e.osError?.errorCode == 54) {
              d.rttMs ??= sw.elapsedMilliseconds;
            }
          } catch (_) {}
        }),
      );
    }
    if (d.openPorts.any((p) => p == 443 || p == 8443)) await _probeTls(d);
    notifyListeners();
  }

  /// A device answering TLS identifies itself in the certificate subject —
  /// IP cameras, printers, NAS and routers all ship vendor certs. Grab the
  /// DN and derive a friendly name + vendor hint from O/CN.
  Future<void> _probeTls(NetworkDevice d) async {
    for (final port in [443, 8443]) {
      if (!d.openPorts.contains(port)) continue;
      try {
        final s = await SecureSocket.connect(
          d.ip,
          port,
          timeout: const Duration(milliseconds: 1500),
          onBadCertificate: (_) => true,
        );
        final cert = s.peerCertificate;
        s.destroy();
        if (cert == null) continue;
        d.tlsSubject = cert.subject;
        d.lastSeenAt = DateTime.now(); // fresh TLS identity evidence
        _applyTlsIdentity(d, cert.subject);
        return;
      } catch (_) {}
    }
  }

  void _applyTlsIdentity(NetworkDevice d, String subject) {
    final org = _dnField(subject, 'O') ?? _dnField(subject, 'CN');
    if (org == null) return;
    final o = org.toLowerCase();
    const names = {
      'foscam': 'Foscam camera',
      'hikvision': 'Hikvision camera',
      'dahua': 'Dahua camera',
      'reolink': 'Reolink camera',
      'amcrest': 'Amcrest camera',
      'axis': 'Axis camera',
      'vivotek': 'Vivotek camera',
      'synology': 'Synology NAS',
      'qnap': 'QNAP NAS',
      'mikrotik': 'MikroTik router',
      'ubiquiti': 'Ubiquiti device',
      'tp-link': 'TP-Link device',
      'tplink': 'TP-Link device',
      'netgear': 'Netgear device',
      'avm': 'FRITZ!Box',
    };
    for (final e in names.entries) {
      if (o.contains(e.key)) {
        d.tlsName = e.value;
        d.vendor ??= e.value.replaceAll(
          RegExp(r' (camera|NAS|router|device)$'),
          '',
        );
        if (d.mdnsName == null) d.nameSource = DeviceNameSource.tls;
        return;
      }
    }
    d.vendor ??= org;
  }

  /// Pulls `O=`/`CN=` out of a `/C=CN/ST=…/O=…/CN=…` DN string.
  static String? _dnField(String subject, String field) {
    final m = RegExp('(?:^|/)\\s*$field=([^/]+)').firstMatch(subject);
    return m?.group(1)?.trim();
  }

  int _hostCount(InterfaceInfo iface) {
    final cidr = iface.cidr;
    if (cidr == null) return 1;
    final prefix = int.parse(cidr.split('/').last);
    return (1 << (32 - prefix)) - 2;
  }

  Future<void> _pool<T>(
    List<T> items,
    int concurrency,
    Future<void> Function(T) fn,
  ) async {
    if (items.isEmpty) return;
    var index = 0;
    await Future.wait(
      List.generate(concurrency.clamp(1, items.length), (_) async {
        while (index < items.length) {
          final i = index++;
          await fn(items[i]);
        }
      }),
    );
  }
}
