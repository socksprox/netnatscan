import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'network_scanner.dart';
import 'oui_db.dart';

/// CoreWLAN facts for the primary interface, when it is Wi-Fi.
/// `ssid`/`bssid` are null when macOS withholds them (Location Services
/// grant required since macOS 14) — `ssidAvailable` distinguishes that.
class WifiInfo {
  final String? interfaceName;
  final String? ssid;
  final bool ssidAvailable;
  final String? bssid;
  final String? security;

  /// Precise security label parsed from the AP's RSN/WPA IEs (e.g.
  /// "WPA2-PSK (CCMP-128)") — null when no scan record was found.
  final String? securityDetail;
  final int? rssi;
  final int? noise;
  final double? transmitRate;
  final int? channel;
  final String? channelBand;
  final String? channelWidth;
  final String? phyMode;
  final String? countryCode;
  final String? mac;

  WifiInfo({
    this.interfaceName,
    this.ssid,
    this.ssidAvailable = false,
    this.bssid,
    this.security,
    this.securityDetail,
    this.rssi,
    this.noise,
    this.transmitRate,
    this.channel,
    this.channelBand,
    this.channelWidth,
    this.phyMode,
    this.countryCode,
    this.mac,
  });

  factory WifiInfo.fromMap(Map<dynamic, dynamic> m) => WifiInfo(
    interfaceName: m['interfaceName'] as String?,
    ssid: m['ssid'] as String?,
    ssidAvailable: m['ssidAvailable'] as bool? ?? false,
    bssid: m['bssid'] as String?,
    security: m['security'] as String?,
    securityDetail: m['securityDetail'] as String?,
    rssi: (m['rssi'] as num?)?.toInt(),
    noise: (m['noise'] as num?)?.toInt(),
    transmitRate: (m['transmitRate'] as num?)?.toDouble(),
    channel: (m['channel'] as num?)?.toInt(),
    channelBand: m['channelBand'] as String?,
    channelWidth: m['channelWidth'] as String?,
    phyMode: m['phyMode'] as String?,
    countryCode: m['countryCode'] as String?,
    mac: m['mac'] as String?,
  );

  /// Signal-to-noise ratio in dB — the honest "signal quality" number.
  int? get snr => (rssi != null && noise != null) ? rssi! - noise! : null;
}

/// One interface's kernel counters (if_data64 via NET_RT_IFLIST2) —
/// bytes/packets/errors accumulate from boot until interface teardown.
class InterfaceStats {
  final String name;
  final int index;
  final int flags;
  final int mtu;
  final int baudrate;
  final int? type;
  final String? mac;
  final int rxBytes;
  final int txBytes;
  final int rxPackets;
  final int txPackets;
  final int rxErrors;
  final int txErrors;
  final int rxQDrops;
  final int collisions;

  InterfaceStats({
    required this.name,
    this.index = 0,
    this.flags = 0,
    this.mtu = 0,
    this.baudrate = 0,
    this.type,
    this.mac,
    this.rxBytes = 0,
    this.txBytes = 0,
    this.rxPackets = 0,
    this.txPackets = 0,
    this.rxErrors = 0,
    this.txErrors = 0,
    this.rxQDrops = 0,
    this.collisions = 0,
  });

  static int _i(Map<dynamic, dynamic> m, String k) =>
      (m[k] as num?)?.toInt() ?? 0;

  factory InterfaceStats.fromMap(String name, Map<dynamic, dynamic> m) =>
      InterfaceStats(
        name: name,
        index: _i(m, 'index'),
        flags: _i(m, 'flags'),
        mtu: _i(m, 'mtu'),
        baudrate: _i(m, 'baudrate'),
        type: (m['type'] as num?)?.toInt(),
        // The if_msghdr2 sockaddr_dl reports a redacted placeholder
        // (02:00:00:00:00:00), not the real MAC — drop it; getNetworkInfo
        // carries the true hardware address.
        mac: m['mac'] == '02:00:00:00:00:00' ? null : m['mac'] as String?,
        rxBytes: _i(m, 'rxBytes'),
        txBytes: _i(m, 'txBytes'),
        rxPackets: _i(m, 'rxPackets'),
        txPackets: _i(m, 'txPackets'),
        rxErrors: _i(m, 'rxErrors'),
        txErrors: _i(m, 'txErrors'),
        rxQDrops: _i(m, 'rxQDrops'),
        collisions: _i(m, 'collisions'),
      );

  // ifm_flags carries the interface's if_flags bits.
  bool get isUp => flags & 0x1 != 0; // IFF_UP
  bool get isRunning => flags & 0x40 != 0; // IFF_RUNNING
  bool get isLoopback => flags & 0x8 != 0; // IFF_LOOPBACK
}

/// Scalar proxy switches from State:/Network/Global/Proxies.
class ProxyInfo {
  final bool httpEnabled;
  final String? httpServer;
  final int? httpPort;
  final bool httpsEnabled;
  final String? httpsServer;
  final int? httpsPort;
  final bool socksEnabled;
  final String? socksServer;
  final int? socksPort;
  final bool autoConfigEnabled;
  final String? autoConfigUrl;
  final List<String> exceptions;

  ProxyInfo({
    this.httpEnabled = false,
    this.httpServer,
    this.httpPort,
    this.httpsEnabled = false,
    this.httpsServer,
    this.httpsPort,
    this.socksEnabled = false,
    this.socksServer,
    this.socksPort,
    this.autoConfigEnabled = false,
    this.autoConfigUrl,
    this.exceptions = const [],
  });

  static bool _b(Map<dynamic, dynamic> m, String k) =>
      (m[k] as num?)?.toInt() == 1;

  factory ProxyInfo.fromMap(Map<dynamic, dynamic> m) => ProxyInfo(
    httpEnabled: _b(m, 'HTTPEnable'),
    httpServer: m['HTTPProxy'] as String?,
    httpPort: (m['HTTPPort'] as num?)?.toInt(),
    httpsEnabled: _b(m, 'HTTPSEnable'),
    httpsServer: m['HTTPSProxy'] as String?,
    httpsPort: (m['HTTPSPort'] as num?)?.toInt(),
    socksEnabled: _b(m, 'SOCKSEnable'),
    socksServer: m['SOCKSProxy'] as String?,
    socksPort: (m['SOCKSPort'] as num?)?.toInt(),
    autoConfigEnabled: _b(m, 'ProxyAutoConfigEnable'),
    autoConfigUrl: m['ProxyAutoConfigURLString'] as String?,
    exceptions:
        (m['exceptions'] as List?)?.map((e) => e.toString()).toList() ??
        const [],
  );

  bool get anyEnabled =>
      httpEnabled || httpsEnabled || socksEnabled || autoConfigEnabled;

  String? get summary {
    final parts = <String>[
      if (httpEnabled && httpServer != null)
        'HTTP $httpServer${httpPort != null ? ':$httpPort' : ''}',
      if (httpsEnabled && httpsServer != null)
        'HTTPS $httpsServer${httpsPort != null ? ':$httpsPort' : ''}',
      if (socksEnabled && socksServer != null)
        'SOCKS $socksServer${socksPort != null ? ':$socksPort' : ''}',
      if (autoConfigEnabled)
        'Auto-config${autoConfigUrl != null ? ' (PAC)' : ''}',
    ];
    return parts.isEmpty ? null : parts.join(' · ');
  }
}

/// DHCP lease scalars decoded from State:/Network/Service/*/DHCP —
/// lease times plus the named `Option_<n>` fields.
class DhcpInfo {
  final String? serverIdentifier;
  final DateTime? leaseStart;
  final DateTime? leaseExpiration;
  final int? leaseDurationSeconds;
  final String? router;
  final String? subnetMask;
  final List<String> dnsServers;
  final String? domainName;

  DhcpInfo({
    this.serverIdentifier,
    this.leaseStart,
    this.leaseExpiration,
    this.leaseDurationSeconds,
    this.router,
    this.subnetMask,
    this.dnsServers = const [],
    this.domainName,
  });

  factory DhcpInfo.fromMap(Map<dynamic, dynamic> m) => DhcpInfo(
    serverIdentifier: m['ServerIdentifier'] as String?,
    leaseStart: _epoch(m['LeaseStartTime']),
    leaseExpiration: _epoch(m['LeaseExpirationTime']),
    leaseDurationSeconds: (m['LeaseDurationSeconds'] as num?)?.toInt(),
    router: m['Router'] as String?,
    subnetMask: m['SubnetMask'] as String?,
    dnsServers:
        (m['DNSServers'] as List?)?.map((e) => e.toString()).toList() ??
        const [],
    domainName: m['DomainName'] as String?,
  );

  static DateTime? _epoch(dynamic v) {
    final s = (v as num?)?.toDouble();
    if (s == null || s <= 0) return null;
    return DateTime.fromMillisecondsSinceEpoch((s * 1000).round());
  }

  DateTime? get leaseEnd =>
      leaseExpiration ??
      (leaseStart != null && leaseDurationSeconds != null
          ? leaseStart!.add(Duration(seconds: leaseDurationSeconds!))
          : null);
}

/// Snapshot of the current uplink — everything `getConnectionInfo`
/// returns on the native side, decoded.
class ConnectionInfo {
  final String? hostname;
  final String? primaryInterface;
  final String networkType;
  final String? defaultGateway;
  final String? ipv6Gateway;
  final WifiInfo? wifi;
  final Map<String, InterfaceStats> interfaces;
  final List<String> dnsServers;
  final List<String> searchDomains;
  final ProxyInfo proxies;
  final DhcpInfo dhcp;
  final DateTime? bootTime;
  final Duration? uptime;

  ConnectionInfo({
    this.hostname,
    this.primaryInterface,
    this.networkType = 'offline',
    this.defaultGateway,
    this.ipv6Gateway,
    this.wifi,
    this.interfaces = const {},
    this.dnsServers = const [],
    this.searchDomains = const [],
    ProxyInfo? proxies,
    DhcpInfo? dhcp,
    this.bootTime,
    this.uptime,
  }) : proxies = proxies ?? ProxyInfo(),
       dhcp = dhcp ?? DhcpInfo();

  factory ConnectionInfo.fromMap(Map<dynamic, dynamic> m) {
    final rawIfaces = m['interfaces'] as Map?;
    final upSecs = (m['uptimeSeconds'] as num?)?.toDouble();
    return ConnectionInfo(
      hostname: m['hostname'] as String?,
      primaryInterface: m['primaryInterface'] as String?,
      networkType: m['networkType'] as String? ?? 'offline',
      defaultGateway: m['defaultGateway'] as String?,
      ipv6Gateway: m['ipv6Gateway'] as String?,
      wifi: m['wifi'] is Map ? WifiInfo.fromMap(m['wifi'] as Map) : null,
      interfaces: {
        if (rawIfaces != null)
          for (final e in rawIfaces.entries)
            e.key.toString(): InterfaceStats.fromMap(
              e.key.toString(),
              e.value as Map,
            ),
      },
      dnsServers:
          (m['dnsServers'] as List?)?.map((e) => e.toString()).toList() ??
          const [],
      searchDomains:
          (m['searchDomains'] as List?)?.map((e) => e.toString()).toList() ??
          const [],
      proxies: m['proxies'] is Map
          ? ProxyInfo.fromMap(m['proxies'] as Map)
          : null,
      dhcp: m['dhcp'] is Map ? DhcpInfo.fromMap(m['dhcp'] as Map) : null,
      bootTime: DhcpInfo._epoch(m['bootTime']),
      uptime: upSecs != null ? Duration(seconds: upSecs.round()) : null,
    );
  }

  InterfaceStats? get primaryStats =>
      primaryInterface != null ? interfaces[primaryInterface] : null;
}

/// Loads and periodically refreshes the current connection snapshot.
/// `reload` is the full refresh (incl. public IP); `refreshStats` is the
/// cheap counter tick the info tab's timer drives for live rates.
class ConnectionInfoService extends ChangeNotifier {
  static const _channel = MethodChannel('netnatscan/network');

  ConnectionInfo? info;
  NetworkInfo? network;
  String? gatewayMac;
  String? gatewayVendor;
  String? publicIp;
  bool publicIpChecked = false;
  double? rxBytesPerSec;
  double? txBytesPerSec;
  bool loading = false;
  String? error;
  DateTime? lastLoadedAt;

  int? _prevRx;
  int? _prevTx;
  DateTime? _prevAt;

  Future<void> reload() => _load(includePublicIp: true);

  Future<void> refreshStats() => _load(includePublicIp: false);

  Future<void> _load({required bool includePublicIp}) async {
    if (loading) return;
    loading = true;
    try {
      await OuiDb.instance.load();
      final raw = await _channel.invokeMapMethod<String, dynamic>(
        'getConnectionInfo',
      );
      if (raw != null) {
        final next = ConnectionInfo.fromMap(raw);
        if (info == null ||
            info!.networkType != next.networkType ||
            info!.wifi?.ssid != next.wifi?.ssid ||
            info!.defaultGateway != next.defaultGateway) {
          debugPrint(
            'netnatscan conn: ${next.networkType} ${next.primaryInterface} '
            'wifi=${next.wifi?.ssid ?? '-'} gw=${next.defaultGateway} '
            'dns=${next.dnsServers}',
          );
        }
        info = next;
      }
      await _refreshNetworkInfo();
      await _resolveGatewayMac();
      _updateRates();
      error = null;
      lastLoadedAt = DateTime.now();
    } catch (e) {
      error = 'Could not read connection info: $e';
    }
    loading = false;
    if (includePublicIp) unawaited(_fetchPublicIp());
    _notify();
  }

  /// In-flight loads (channel round-trips, the public-IP fetch) can
  /// complete after the owning screen disposed us — skip notifying dead
  /// listeners.
  bool _disposed = false;

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }

  Future<void> _refreshNetworkInfo() async {
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
    } catch (e) {
      debugPrint('netnatscan conn: getNetworkInfo failed: $e');
    }
  }

  /// The router's MAC is already definitive — it is an ARP neighbour
  /// like every other LAN host, and the OUI lookup reveals the vendor.
  Future<void> _resolveGatewayMac() async {
    final gw = info?.defaultGateway;
    if (gw == null) return;
    try {
      final rows =
          await _channel.invokeListMethod<Map<dynamic, dynamic>>(
            'getArpTable',
          ) ??
          [];
      for (final r in rows) {
        if (r['ip'] == gw) {
          gatewayMac = r['mac'] as String?;
          gatewayVendor = gatewayMac != null
              ? OuiDb.instance.lookup(gatewayMac!)
              : null;
          return;
        }
      }
    } catch (_) {}
  }

  void _updateRates() {
    final stats = info?.primaryStats;
    final now = DateTime.now();
    if (stats != null && _prevAt != null && _prevRx != null) {
      final dt = now.difference(_prevAt!).inMilliseconds / 1000.0;
      if (dt > 0) {
        rxBytesPerSec = (stats.rxBytes - _prevRx!) / dt;
        txBytesPerSec = (stats.txBytes - _prevTx!) / dt;
      }
    }
    if (stats != null) {
      _prevRx = stats.rxBytes;
      _prevTx = stats.txBytes;
      _prevAt = now;
    }
  }

  /// Public IP via a lightweight HTTPS call — the only off-LAN probe
  /// in the app; failure just leaves the field blank.
  Future<void> _fetchPublicIp() async {
    if (Platform.environment['FLUTTER_TEST'] == 'true') {
      publicIpChecked = true;
      return;
    }
    String? ip;
    try {
      final client = HttpClient()
        ..connectionTimeout = const Duration(seconds: 3);
      try {
        final req = await client.getUrl(Uri.parse('https://api.ipify.org'));
        final resp = await req.close().timeout(const Duration(seconds: 3));
        final body = await resp.transform(utf8.decoder).join();
        final trimmed = body.trim();
        if (RegExp(
          r'^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$',
        ).hasMatch(trimmed)) {
          ip = trimmed;
        }
      } finally {
        client.close();
      }
    } catch (_) {}
    publicIp = ip;
    publicIpChecked = true;
    _notify();
  }
}
