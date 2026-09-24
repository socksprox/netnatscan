/// Windows implementation of the `netnatscan/network` method surface —
/// the counterpart of macos/Runner/NetworkPlugin.swift. No plugin code
/// is needed on Windows: there is no sandbox, so everything runs
/// in-process via dart:ffi (iphlpapi/wlanapi/advapi32/ws2_32) or plain
/// dart:io sockets.
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';
import 'package:win32/win32.dart';

import 'win32_ffi.dart' as w;
import 'win32_tools.dart';
import 'win32_wlan.dart' as wlan;

/// One network adapter distilled from GetAdaptersAddresses.
class WinAdapter {
  String name = ''; // friendly name, shown in the UI ("Wi-Fi")
  String adapterName = ''; // "{GUID}" — stable key for registry lookups
  int ifIndex = 0;
  int ipv6IfIndex = 0;
  int ifType = 0;
  bool isUp = false;
  String? mac;
  final List<(String ip, String netmask)> ipv4 = [];
  final List<String> ipv6 = [];
  final List<String> gateways4 = [];
  final List<String> gateways6 = [];
  final List<String> dns = [];
  String? dnsSuffix;
  bool dhcpv4 = false;
  int ipv4Metric = 0;

  bool get isLoopback => ifType == 24; // IF_TYPE_SOFTWARE_LOOPBACK
}

/// All adapters via GetAdaptersAddresses (two-call size probe).
List<WinAdapter> getAdapters() {
  return using((arena) {
    final sizePtr = arena<Uint32>();
    var r = GetAdaptersAddresses(
        0, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, sizePtr);
    if (r != 111 /* ERROR_BUFFER_OVERFLOW */ || sizePtr.value == 0) {
      return const <WinAdapter>[];
    }
    final buf = arena<Uint8>(sizePtr.value)
        .cast<IP_ADAPTER_ADDRESSES_LH>();
    r = GetAdaptersAddresses(0, GAA_FLAG_INCLUDE_GATEWAYS, buf, sizePtr);
    if (r != 0) return const <WinAdapter>[];

    final out = <WinAdapter>[];
    var p = buf;
    while (p != nullptr) {
      final a = p.ref;
      final ad = WinAdapter()
        ..name = a.FriendlyName.toDartString()
        ..adapterName = a.AdapterName.toDartString()
        ..ifIndex = a.IfIndex
        ..ipv6IfIndex = a.Ipv6IfIndex
        ..ifType = a.IfType
        ..isUp = a.OperStatus == IfOperStatusUp
        ..ipv4Metric = a.Ipv4Metric;
      if (ad.name.isEmpty) ad.name = a.Description.toDartString();
      if (a.PhysicalAddressLength == 6) {
        ad.mac = w.macString(a.PhysicalAddress, 6);
      }

      var ua = a.FirstUnicastAddress;
      while (ua != nullptr) {
        final u = ua.ref;
        final sa = u.Address;
        final str = w.sockaddrToString(
            sa.lpSockaddr, sa.iSockaddrLength);
        if (str != null) {
          if (str.contains(':')) {
            if (str != '::1') ad.ipv6.add(str);
          } else {
            ad.ipv4.add((str, _prefixToMask(u.OnLinkPrefixLength)));
          }
        }
        ua = u.Next;
      }

      var gw = a.FirstGatewayAddress;
      while (gw != nullptr) {
        final g = gw.ref.Address;
        final str =
            w.sockaddrToString(g.lpSockaddr, g.iSockaddrLength);
        if (str != null) {
          if (str.contains(':')) {
            ad.gateways6.add(str);
          } else if (str != '0.0.0.0') {
            ad.gateways4.add(str);
          }
        }
        gw = gw.ref.Next;
      }

      var dn = a.FirstDnsServerAddress;
      while (dn != nullptr) {
        final d = dn.ref.Address;
        final str =
            w.sockaddrToString(d.lpSockaddr, d.iSockaddrLength);
        if (str != null) ad.dns.add(str);
        dn = dn.ref.Next;
      }

      final suffix = a.DnsSuffix.toDartString();
      if (suffix.isNotEmpty) ad.dnsSuffix = suffix;
      ad.dhcpv4 = a.Dhcpv4Server.lpSockaddr != nullptr;
      out.add(ad);
      p = a.Next;
    }
    return out;
  });
}

String _prefixToMask(int prefix) {
  if (prefix <= 0 || prefix > 32) return '0.0.0.0';
  final v = prefix == 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) & 0xffffffff;
  return '${(v >> 24) & 255}.${(v >> 16) & 255}.${(v >> 8) & 255}.${v & 255}';
}

/// The default-route adapter: GetBestRoute2 to a public address, else the
/// up adapter with a gateway and the lowest IPv4 metric.
(WinAdapter?, String?) _defaultRoute(List<WinAdapter> ads) {
  final route = w.bestRouteV4();
  if (route.ifIndex != null) {
    for (final a in ads) {
      if (a.ifIndex == route.ifIndex) {
        final gw = route.gateway ??
            (a.gateways4.isNotEmpty ? a.gateways4.first : null);
        return (a, gw);
      }
    }
  }
  WinAdapter? best;
  for (final a in ads) {
    if (!a.isUp || a.isLoopback || a.gateways4.isEmpty) continue;
    if (best == null || a.ipv4Metric < best.ipv4Metric) best = a;
  }
  return (best, best?.gateways4.first);
}

Map<int, String> _ifIndexToName(List<WinAdapter> ads) => {
      for (final a in ads) a.ifIndex: a.name,
      for (final a in ads) if (a.ipv6IfIndex != 0) a.ipv6IfIndex: a.name,
    };

// -- getNetworkInfo ------------------------------------------------------------

Map<String, Object?> getNetworkInfo() {
  final ads = getAdapters();
  final (primary, gateway) = _defaultRoute(ads);
  final interfaces = <Map<String, Object?>>[
    for (final a in ads)
      for (final (ip, mask) in a.ipv4)
        {
          'name': a.name,
          'ip': ip,
          'netmask': mask,
          if (a.mac != null) 'mac': a.mac,
          if (a.ipv6.isNotEmpty) 'ipv6': a.ipv6,
          'isUp': a.isUp,
          'isLoopback': a.isLoopback,
        },
  ];
  return {
    'interfaces': interfaces,
    'defaultGateway': gateway,
    'defaultInterface': primary?.name,
  };
}

// -- getArpTable / getNdpTable --------------------------------------------------

List<Map<String, Object?>> getArpTable() =>
    w.ipNetTable(w.afInet, (i) => _ifIndexToName(getAdapters())[i] ?? '');

List<Map<String, Object?>> getNdpTable() =>
    w.ipNetTable(w.afInet6, (i) => _ifIndexToName(getAdapters())[i] ?? '');

// -- triggerNdp -----------------------------------------------------------------

/// IPv6 twin of the UDP blast: datagrams to the all-nodes multicast
/// ff02::1 on the named interface — same mechanism as the macOS side.
void triggerNdp(String? interfaceName) {
  if (interfaceName == null) return;
  WinAdapter? target;
  for (final a in getAdapters()) {
    if (a.name == interfaceName) {
      target = a;
      break;
    }
  }
  final scope = target?.ipv6IfIndex ?? 0;
  if (scope == 0) return;
  using((arena) {
    final fd = w.wsaSocket(w.afInet6, w.sockDgram, w.ipprotoUdp);
    if (fd == -1 || fd == 0) return;
    try {
      final dst = w.sockaddrIn6(arena, InternetAddress('ff02::1'),
          scopeId: scope, port: 44444);
      final payload = arena<Uint8>(1);
      for (var i = 0; i < 3; i++) {
        w.wsaSendto(fd, payload, 1, 0, dst.cast(), 28);
        w.sleepMs(120);
      }
    } finally {
      w.wsaClose(fd);
    }
  });
}

// -- getConnectionInfo -----------------------------------------------------------

Map<String, Object?> getConnectionInfo() {
  final ads = getAdapters();
  final byIndex = _ifIndexToName(ads);
  final (primary, gateway) = _defaultRoute(ads);

  final stats = <String, Map<String, Object?>>{};
  for (final e in w.ifTableStats().entries) {
    final name = byIndex[e.key];
    if (name != null && name.isNotEmpty) stats[name] = e.value;
  }

  Map<String, Object?>? wifi;
  if (primary != null && primary.ifType == 71 /* IF_TYPE_IEEE80211 */) {
    wifi = wlan.currentConnection(primary.adapterName, primary.name,
        mac: primary.mac);
  }

  final dns = <String>{};
  for (final a in ads) {
    if (!a.isUp || a.isLoopback) continue;
    dns.addAll(a.dns);
  }

  final payload = <String, Object?>{
    'hostname': Platform.localHostname,
    'primaryInterface': primary?.name,
    'networkType': primary == null
        ? 'offline'
        : wifi != null
            ? 'wifi'
            : primary.ifType == 6
                ? 'ethernet'
                : 'other',
    'defaultGateway': gateway,
    'ipv6Gateway': primary?.gateways6.isNotEmpty == true
        ? primary!.gateways6.first
        : null,
    'wifi': ?wifi,
    'interfaces': stats,
    'dnsServers': dns.toList(),
    'searchDomains': [
      if (primary?.dnsSuffix?.isNotEmpty == true) primary!.dnsSuffix!,
    ],
    'proxies': _proxyInfo(),
    'dhcp': _dhcpInfo(primary?.adapterName),
  };

  final uptimeMs = w.getTickCount64();
  final bootEpoch = DateTime.now().millisecondsSinceEpoch / 1000 -
      uptimeMs / 1000;
  payload['bootTime'] = bootEpoch;
  payload['uptimeSeconds'] = uptimeMs / 1000;
  return payload;
}

// -- registry --------------------------------------------------------------------

/// Reads a REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ value as strings.
List<String> _regStrings(
    HKEY root, String subKey, String value) {
  return using((arena) {
    final size = arena<Uint32>();
    final sub = PCWSTR(subKey.toNativeUtf16(allocator: arena));
    final val = PCWSTR(value.toNativeUtf16(allocator: arena));
    var r = RegGetValue(
        root, sub, val, RRF_RT_ANY, nullptr, nullptr, size);
    if (r != ERROR_SUCCESS || size.value == 0) return const [];
    final buf = arena<Uint8>(size.value);
    r = RegGetValue(root, sub, val, RRF_RT_ANY, nullptr, buf.cast(), size);
    if (r != ERROR_SUCCESS) return const [];
    // UTF-16 buffer; MULTI_SZ entries are NUL-separated.
    final units = <int>[
      for (var i = 0; i + 1 < size.value; i += 2)
        buf[i] | (buf[i + 1] << 8),
    ];
    final text = String.fromCharCodes(units)
        .replaceAll(RegExp(r'\x00+$'), '');
    return text.split('\x00').where((s) => s.isNotEmpty).toList();
  });
}

int? _regDword(HKEY root, String subKey, String value) {
  return using((arena) {
    final size = arena<Uint32>()..value = 4;
    final out = arena<Uint32>();
    final sub = PCWSTR(subKey.toNativeUtf16(allocator: arena));
    final val = PCWSTR(value.toNativeUtf16(allocator: arena));
    final r = RegGetValue(
        root, sub, val, RRF_RT_REG_DWORD, nullptr, out.cast(), size);
    return r == ERROR_SUCCESS ? out.value : null;
  });
}

Map<String, Object?> _proxyInfo() {
  const key =
      r'Software\Microsoft\Windows\CurrentVersion\Internet Settings';
  final enabled = _regDword(HKEY_CURRENT_USER, key, 'ProxyEnable') == 1;
  final server = _regStrings(HKEY_CURRENT_USER, key, 'ProxyServer')
      .firstOrNull;
  final override =
      _regStrings(HKEY_CURRENT_USER, key, 'ProxyOverride').firstOrNull;
  final pacUrl =
      _regStrings(HKEY_CURRENT_USER, key, 'AutoConfigURL').firstOrNull;

  final out = <String, Object?>{};
  if (enabled && server != null && server.isNotEmpty) {
    // "host:port" applies to every scheme; "http=..;https=..;socks=.."
    // maps per protocol.
    for (final part in server.split(';')) {
      final eq = part.indexOf('=');
      final scheme = eq > 0 ? part.substring(0, eq).trim() : '';
      var hp = (eq > 0 ? part.substring(eq + 1) : part).trim();
      hp = hp.replaceAll(RegExp(r'^\w+://'), '');
      final host = hp.split(':').first;
      final port = int.tryParse(hp.split(':').last);
      void set(String en, String h, String p) {
        out[en] = 1;
        out[h] = host;
        if (port != null) out[p] = port;
      }

      switch (scheme) {
        case 'http':
          set('HTTPEnable', 'HTTPProxy', 'HTTPPort');
        case 'https':
          set('HTTPSEnable', 'HTTPSProxy', 'HTTPSPort');
        case 'socks':
          set('SOCKSEnable', 'SOCKSProxy', 'SOCKSPort');
        default:
          set('HTTPEnable', 'HTTPProxy', 'HTTPPort');
          set('HTTPSEnable', 'HTTPSProxy', 'HTTPSPort');
      }
    }
  }
  if (pacUrl != null && pacUrl.isNotEmpty) {
    out['ProxyAutoConfigEnable'] = 1;
    out['ProxyAutoConfigURLString'] = pacUrl;
  }
  if (override != null && override.isNotEmpty) {
    out['exceptions'] = override
        .split(';')
        .map((e) => e.trim())
        .where((e) => e.isNotEmpty)
        .toList();
  }
  return out;
}

/// DHCP lease scalars from HKLM\...\Tcpip\Parameters\Interfaces\{guid} —
/// populated only when the adapter actually got a DHCP lease.
Map<String, Object?> _dhcpInfo(String? adapterName) {
  if (adapterName == null) return const {};
  final key =
      r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'
      '$adapterName';
  final obtained =
      _regDword(HKEY_LOCAL_MACHINE, key, 'LeaseObtainedTime');
  if (obtained == null || obtained == 0) return const {};
  final out = <String, Object?>{
    'LeaseStartTime': obtained.toDouble(),
  };
  final expires =
      _regDword(HKEY_LOCAL_MACHINE, key, 'LeaseTerminatesTime');
  if (expires != null && expires != 0) {
    out['LeaseExpirationTime'] = expires.toDouble();
    if (expires > obtained) {
      out['LeaseDurationSeconds'] = expires - obtained;
    }
  }
  String? s(String v) {
    final l = _regStrings(HKEY_LOCAL_MACHINE, key, v);
    return l.isEmpty ? null : l.first;
  }

  if (s('DhcpServer') case final v?) out['ServerIdentifier'] = v;
  if (s('DhcpDefaultGateway') case final v?) out['Router'] = v;
  if (s('DhcpSubnetMask') case final v?) out['SubnetMask'] = v;
  if (s('Domain') case final v?) {
    if (v.isNotEmpty) out['DomainName'] = v;
  }
  final nameServers = s('DhcpNameServer');
  if (nameServers != null) {
    out['DNSServers'] = nameServers
        .split(RegExp(r'[,\s]+'))
        .where((e) => e.isNotEmpty)
        .toList();
  }
  return out;
}

// -- dispatcher -------------------------------------------------------------------

/// Mirrors NetworkPlugin.handle() — the method surface the Dart services
/// call on macOS. Blocking calls that take seconds (the Wi-Fi scan) go
/// to a worker isolate; everything else completes in milliseconds.
class Win32Backend {
  static Future<Object?> invoke(String method, [dynamic args]) async {
    switch (method) {
      case 'getNetworkInfo':
        return getNetworkInfo();
      case 'getArpTable':
        return getArpTable();
      case 'getNdpTable':
        return getNdpTable();
      case 'triggerNdp':
        triggerNdp(args as String?);
        return null;
      case 'startPing':
      case 'startRoute':
        return Win32ToolEngine.instance
            .start(method, args as Map? ?? const {});
      case 'stopTool':
        Win32ToolEngine.instance.stop();
        return null;
      case 'getConnectionInfo':
        return getConnectionInfo();
      case 'getWifiNetworks':
        return Isolate.run(wlan.scanNetworks);
      default:
        throw UnsupportedError('unimplemented method $method');
    }
  }
}
