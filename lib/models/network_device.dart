import 'dart:io';

import 'package:flutter/material.dart';

import '../services/mdns_discovery.dart';
import '../services/nbns_discovery.dart';
import '../services/ssdp_discovery.dart';

enum DeviceType {
  thisDevice,
  router,
  computer,
  phone,
  tablet,
  tv,
  printer,
  speaker,
  camera,
  iot,
  vm,
  unknown,
}

/// How the displayed name was learned — the user should always be able
/// to tell a Bonjour-advertised name from a cache restore or an OUI guess.
enum DeviceNameSource {
  none,
  local,
  dns,
  mdnsPtr,
  mdnsHost,
  mdnsInstance,
  cache,
  vendor,
  gateway,
  tls,
  ssdp,
  netbios,
  http,
}

class NetworkDevice {
  final String ip;
  String? hostname;
  String? mdnsName;
  final Set<String> mdnsTypes = {};
  final String? mac;
  String? vendor;
  int? rttMs;
  bool isGateway;
  bool isSelf;
  bool respondedToProbe;

  /// The device answered no mDNS this scan — its identity was restored
  /// from the persistent name cache. Typical for phones in standby,
  /// which keep their ARP entry via the Wi-Fi chip but go silent at L7.
  bool isStandby;

  /// Bonjour services this device advertised live in the latest scan.
  final List<MdnsService> mdnsServices = [];

  /// When its identity was last learned live (cache timestamp when
  /// restored, `now` when answered).
  DateTime? lastSeenAt;

  /// Provenance of [displayName] — which record produced the winning
  /// name, plus a detail like the service type it came through.
  DeviceNameSource nameSource;
  String? nameSourceDetail;

  /// Every other name this device was seen under (services, hosts,
  /// PTRs) — shown in the detail view so the chosen name stays auditable.
  final Set<String> seenNames = {};

  /// TCP ports that accepted a connection — a fingerprint for devices
  /// that never speak mDNS (cameras, printers, IoT hubs).
  final Set<int> openPorts = {};

  /// The peer's TLS certificate subject when a TLS port answered
  /// (`/O=Shenzhen Foscam…/CN=*.myfoscam.org`) and a friendly name
  /// derived from it ("Foscam camera").
  String? tlsSubject;
  String? tlsName;

  /// UPnP/SSDP self-description when the device answered M-SEARCH —
  /// friendlyName, manufacturer, model, device-type URN, server header.
  SsdpDevice? upnp;

  /// NetBIOS names from a UDP/137 node-status answer — Windows hosts,
  /// Samba NASes and some printers identify themselves this way.
  final List<NbnsName> netbiosNames = [];

  /// HTTP Server header and page <title> when a port scan found a web
  /// admin interface — routers/cameras/NASes self-identify there.
  String? httpServer;
  String? httpTitle;

  /// IPv6 addresses (link-local `%ifname`-scoped, ULA, global) learned
  /// from the kernel NDP table — matched by MAC — or the device's own
  /// mDNS AAAA records.
  final Set<String> ipv6Addresses = {};

  NetworkDevice({
    required this.ip,
    this.hostname,
    this.mdnsName,
    this.mac,
    this.vendor,
    this.rttMs,
    this.isGateway = false,
    this.isSelf = false,
    this.respondedToProbe = false,
    this.isStandby = false,
    this.nameSource = DeviceNameSource.none,
  });

  /// Adds an IPv6 literal in canonical compressed form so NDP- and
  /// AAAA-learned duplicates collapse (`fe80:0:0:0:x` == `fe80::x`).
  /// The same address with and without a `%ifname` zone counts once —
  /// the scoped spelling is kept since it is the usable literal.
  void addIpv6(String addr) {
    final zone = addr.indexOf('%');
    final core = zone >= 0 ? addr.substring(0, zone) : addr;
    final suffix = zone >= 0 ? addr.substring(zone) : '';
    final parsed = InternetAddress.tryParse(core);
    if (parsed == null || parsed.rawAddress.length != 16) return;
    final canon = _compressV6(parsed.rawAddress);
    final dup = ipv6Addresses
        .where((e) => e.split('%').first == canon)
        .firstOrNull;
    if (dup != null) {
      if (suffix.isNotEmpty && !dup.contains('%')) {
        ipv6Addresses
          ..remove(dup)
          ..add('$canon$suffix');
      }
      return;
    }
    ipv6Addresses.add('$canon$suffix');
  }

  /// Global/ULA first, link-local last — those identify the device
  /// better; fe80::/10 is the per-interface fallback every host has.
  List<String> get sortedIpv6 {
    final list = ipv6Addresses.toList();
    list.sort((a, b) {
      final la = _isV6LinkLocal(a), lb = _isV6LinkLocal(b);
      if (la != lb) return la ? 1 : -1;
      return a.compareTo(b);
    });
    return list;
  }

  static bool _isV6LinkLocal(String a) {
    final first = int.tryParse(a.split(':').first, radix: 16) ?? 0;
    return first & 0xffc0 == 0xfe80;
  }

  /// 16 bytes -> canonical form; the longest zero run (>= 2) -> `::`.
  static String _compressV6(List<int> b) {
    final words = [for (var i = 0; i < 8; i++) (b[i * 2] << 8) | b[i * 2 + 1]];
    var bestStart = -1, bestLen = 0;
    var i = 0;
    while (i < 8) {
      if (words[i] != 0) {
        i++;
        continue;
      }
      var j = i;
      while (j < 8 && words[j] == 0) {
        j++;
      }
      if (j - i > bestLen) {
        bestStart = i;
        bestLen = j - i;
      }
      i = j;
    }
    final hex = [for (final w in words) w.toRadixString(16)];
    if (bestLen < 2) return hex.join(':');
    return '${hex.sublist(0, bestStart).join(':')}::'
        '${hex.sublist(bestStart + bestLen).join(':')}';
  }

  DeviceType get type => _classify();

  /// Best human-facing name: Bonjour instance name > PTR hostname > vendor.
  String get displayName {
    if (mdnsName != null && mdnsName!.isNotEmpty) return mdnsName!;
    if (hostname != null && hostname!.isNotEmpty) return hostname!;
    if (isGateway) return 'Router';
    if (tlsName != null && tlsName!.isNotEmpty) return tlsName!;
    if (vendor != null && vendor!.isNotEmpty) return '$vendor device';
    return 'Unknown device';
  }

  /// What produced [displayName] — falls back to the implicit sources
  /// (gateway label, OUI vendor) when no name record set it.
  DeviceNameSource get effectiveNameSource =>
      nameSource != DeviceNameSource.none
      ? nameSource
      : isGateway
      ? DeviceNameSource.gateway
      : (vendor != null && vendor!.isNotEmpty)
      ? DeviceNameSource.vendor
      : DeviceNameSource.none;

  String get nameSourceLabel => switch (effectiveNameSource) {
    DeviceNameSource.mdnsPtr => 'PTR record',
    DeviceNameSource.mdnsHost => 'mDNS hostname',
    DeviceNameSource.mdnsInstance => 'service name',
    DeviceNameSource.dns => 'DNS PTR',
    DeviceNameSource.cache => 'cached',
    DeviceNameSource.local => 'local',
    DeviceNameSource.vendor => 'OUI guess',
    DeviceNameSource.gateway => 'gateway',
    DeviceNameSource.tls => 'TLS cert',
    DeviceNameSource.ssdp => 'UPnP name',
    DeviceNameSource.netbios => 'NetBIOS',
    DeviceNameSource.http => 'HTTP title',
    DeviceNameSource.none => '',
  };

  /// `service name · _androidtvremote2`, `cached`, `OUI guess`, …
  String get nameSourceText {
    final base = nameSourceLabel;
    return base.isNotEmpty && nameSourceDetail != null
        ? '$base · $nameSourceDetail'
        : base;
  }

  IconData get icon => switch (type) {
    DeviceType.thisDevice => Icons.laptop_mac,
    DeviceType.router => Icons.router,
    DeviceType.computer => Icons.computer,
    DeviceType.phone => Icons.smartphone,
    DeviceType.tablet => Icons.tablet_mac,
    DeviceType.tv => Icons.tv,
    DeviceType.printer => Icons.print,
    DeviceType.speaker => Icons.speaker,
    DeviceType.camera => Icons.videocam_outlined,
    DeviceType.iot => Icons.memory,
    DeviceType.vm => Icons.cloud_queue,
    DeviceType.unknown => Icons.device_unknown,
  };

  String get typeLabel => switch (type) {
    DeviceType.thisDevice => 'This device',
    DeviceType.router => 'Router',
    DeviceType.computer => 'Computer',
    DeviceType.phone => 'Phone',
    DeviceType.tablet => 'Tablet',
    DeviceType.tv => 'TV',
    DeviceType.printer => 'Printer',
    DeviceType.speaker => 'Speaker',
    DeviceType.camera => 'Camera',
    DeviceType.iot => 'Smart device',
    DeviceType.vm => 'Virtual machine',
    DeviceType.unknown => 'Device',
  };

  /// mDNS service types → device type, checked in order (most specific first).
  static const _mdnsTypeRules = <String, DeviceType>{
    '_airplay': DeviceType.tv,
    '_nvstream': DeviceType.tv,
    '_googlecast': DeviceType.tv,
    '_raop': DeviceType.speaker,
    '_sonos': DeviceType.speaker,
    '_spotify-connect': DeviceType.speaker,
    '_ipp': DeviceType.printer,
    '_ipps': DeviceType.printer,
    '_printer': DeviceType.printer,
    '_pdl-datastream': DeviceType.printer,
    '_companion-link': DeviceType.phone,
    '_apple-mobdev2': DeviceType.phone,
    '_smb': DeviceType.computer,
    '_afpovertcp': DeviceType.computer,
    '_device-info': DeviceType.computer,
    '_workstation': DeviceType.computer,
    '_ssh': DeviceType.computer,
    '_adisk': DeviceType.computer,
    '_hap': DeviceType.iot,
    '_homekit': DeviceType.iot,
    '_matter': DeviceType.iot,
    '_esphome': DeviceType.iot,
  };

  DeviceType _classify() {
    if (isSelf) return DeviceType.thisDevice;
    if (isGateway) return DeviceType.router;

    final h = (mdnsName ?? hostname ?? '').toLowerCase();
    final v = vendor?.toLowerCase() ?? '';

    // Explicit product names beat service hints — a MacBook Air that
    // advertises AirPlay is still a computer, not a TV.
    if (_has(h, ['iphone'])) return DeviceType.phone;
    if (_has(h, ['ipad'])) return DeviceType.tablet;
    if (_has(h, [
      'macbook',
      'imac',
      'mac-mini',
      'mac-studio',
      'mac-pro',
      'macpro',
      'desktop',
      'laptop',
      '-pc',
    ])) {
      return DeviceType.computer;
    }
    if (_has(h, ['watch'])) return DeviceType.iot;
    if (_has(h, ['appletv', 'apple-tv'])) return DeviceType.tv;

    // Advertised Bonjour services are strong evidence of what a device is.
    for (final t in mdnsTypes) {
      final rule = _mdnsTypeRules[t];
      if (rule != null) return rule;
    }

    // UPnP device-type URNs — the device's own self-description, same
    // tier of evidence as Bonjour service types.
    final urn = '${upnp?.deviceType ?? ''} ${upnp?.sts.join(' ') ?? ''}'
        .toLowerCase();
    if (urn.isNotEmpty) {
      if (_has(urn, [
        'internetgatewaydevice',
        'wandevice',
        'wanconnectiondevice',
      ])) {
        return DeviceType.router;
      }
      if (_has(urn, ['dial-multiscreen', 'mediarenderer', 'mediaserver'])) {
        return DeviceType.tv;
      }
      if (_has(urn, ['digitalsecuritycamera', 'networkcamera'])) {
        return DeviceType.camera;
      }
      if (_has(urn, ['printer'])) return DeviceType.printer;
      if (_has(urn, ['scanner'])) return DeviceType.printer;
    }
    // UPnP manufacturer / SERVER header keywords.
    final upnpText =
        '${upnp?.manufacturer ?? ''} ${upnp?.modelName ?? ''} '
                '${upnp?.server ?? ''}'
            .toLowerCase();
    if (_has(upnpText, [
      'foscam',
      'hikvision',
      'dahua',
      'reolink',
      'amcrest',
      'axis',
      'vivotek',
      'ipcam',
      'netcam',
    ])) {
      return DeviceType.camera;
    }
    if (_has(upnpText, ['synology', 'qnap', 'nas', 'diskstation'])) {
      return DeviceType.computer;
    }

    // TLS cert names are explicit self-identification ("Foscam camera").
    if (tlsName != null) {
      final t = tlsName!.toLowerCase();
      if (_has(t, [
        'foscam',
        'hikvision',
        'dahua',
        'reolink',
        'amcrest',
        'axis',
        'vivotek',
        'unifi protect',
        'camera',
      ])) {
        return DeviceType.camera;
      }
      if (_has(t, ['synology', 'qnap', 'nas'])) return DeviceType.computer;
      if (_has(t, ['mikrotik', 'ubiquiti', 'router'])) {
        return DeviceType.router;
      }
    }

    // Open-port fingerprints for devices that never speak mDNS.
    // 62078 is Apple's lockdownd pairing — iOS-only, Macs never listen.
    if (openPorts.contains(62078)) return DeviceType.phone;
    if (openPorts.contains(554)) return DeviceType.camera; // RTSP
    if (openPorts.contains(8008) || openPorts.contains(8009)) {
      return DeviceType.tv; // Chromecast
    }
    if (openPorts.contains(9100) || openPorts.contains(631)) {
      return DeviceType.printer;
    }
    if (openPorts.contains(7000)) return DeviceType.tv; // AirPlay
    if (openPorts.contains(8291)) return DeviceType.router; // Winbox
    if (openPorts.contains(445) || openPorts.contains(548)) {
      return DeviceType.computer; // SMB / AFP
    }
    // A NetBIOS name table means a Windows/Samba host — computer or NAS.
    if (netbiosNames.isNotEmpty) return DeviceType.computer;

    // Remaining hostname hints.
    if (_has(h, ['homepod', 'echo', 'alexa', 'sonos'])) {
      return DeviceType.speaker;
    }
    if (_has(h, ['appletv', 'apple-tv', 'bravia', '-tv', 'tv-'])) {
      return DeviceType.tv;
    }
    if (_has(h, ['android', 'galaxy'])) return DeviceType.phone;
    if (_has(h, ['print'])) return DeviceType.printer;
    if (_has(h, ['raspberrypi', 'raspberry-pi'])) return DeviceType.iot;
    if (_has(h, ['router', 'gateway', 'fritz.box'])) return DeviceType.router;
    if (_has(h, ['nas', 'synology', 'qnap'])) return DeviceType.computer;

    // Vendor heuristics.
    if (_has(v, [
      'netgear',
      'tp-link',
      'd-link',
      'linksys',
      'cisco',
      'ubiquiti',
      'mikrotik',
      'avm',
      'arris',
      'zyxel',
      'netgate',
      'ruckus',
      'aruba',
      'eero',
      'gl-inet',
      'juniper',
      'edgecore',
    ])) {
      return DeviceType.router;
    }
    if (_has(v, ['apple'])) return DeviceType.computer;
    if (_has(v, [
      'epson',
      'canon',
      'brother',
      'kyocera',
      'xerox',
      'ricoh',
      'lexmark',
      'zebra',
    ])) {
      return DeviceType.printer;
    }
    if (_has(v, [
      'lg ',
      'sony',
      'tcl',
      'hisense',
      'vizio',
      'roku',
      'sharp',
      'philips',
      'panasonic',
      'samsung',
    ])) {
      return DeviceType.tv;
    }
    if (_has(v, [
      'sonos',
      'bose',
      'denon',
      'harman',
      'bang & olufsen',
      'bowers',
    ])) {
      return DeviceType.speaker;
    }
    if (_has(v, [
      'espressif',
      'tuya',
      'allterco',
      'itead',
      'ring',
      'nest',
      'ecobee',
      'signify',
      'lifx',
      'nanoleaf',
      'wyze',
      'raspberry pi',
      'amazon',
      'google',
    ])) {
      return DeviceType.iot;
    }
    if (_has(v, [
      'vmware',
      'parallels',
      'innotek',
      'virtualbox',
      'qemu',
      'hyper-v',
      'xensource',
    ])) {
      return DeviceType.vm;
    }
    if (_has(v, [
      'xiaomi',
      'huawei',
      'oppo',
      'vivo',
      'oneplus',
      'motorola',
      'honor',
    ])) {
      return DeviceType.phone;
    }
    if (_has(v, [
      'intel',
      'dell',
      'lenovo',
      'hewlett',
      'asustek',
      'microsoft',
      'gigabyte',
      'msi',
      'acer',
      'liteon',
      'foxconn',
      'quanta',
      'compal',
      'wistron',
      'pegatron',
    ])) {
      return DeviceType.computer;
    }
    return DeviceType.unknown;
  }

  static bool _has(String haystack, List<String> needles) {
    for (final n in needles) {
      if (haystack.contains(n)) return true;
    }
    return false;
  }
}
