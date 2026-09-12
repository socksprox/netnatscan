import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../models/network_device.dart';
import 'mdns_discovery.dart';
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
        '${result.deviceNames.length} hostnames',
      );
      final byIp = {for (final d in devices) d.ip: d};
      // Reverse-PTR announcements carry the device's own pretty hostname
      // ("iPhone-16-Pro-Max-von-Tamino") — better than instance names.
      for (final e in result.deviceNames.entries) {
        final d = byIp[e.key];
        if (d == null) continue;
        d.mdnsName ??= e.value;
        d.hostname ??= e.value;
      }
      for (final svc in result.services) {
        final type = svc.type
            .toLowerCase()
            .replaceAll(RegExp(r'\.$'), '')
            .replaceAll(RegExp(r'\._(tcp|udp)$'), '');
        for (final ip in svc.ips) {
          final d = byIp[ip];
          if (d == null) continue;
          if (svc.name.isNotEmpty) {
            d.mdnsName ??= svc.name;
            d.hostname ??= svc.name;
          }
          if (type.isNotEmpty) d.mdnsTypes.add(type);
        }
      }
      notifyListeners();
    } catch (e) {
      debugPrint('netnatscan: mDNS discovery failed: $e');
    }
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
      }
    } catch (_) {}
  }

  /// TCP connect gives us an RTT without raw sockets: both a completed
  /// handshake and a refused connection prove the host is alive and time it.
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
        d.rttMs = sw.elapsedMilliseconds;
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
