import 'package:flutter/material.dart';

enum DeviceType {
  thisDevice,
  router,
  computer,
  phone,
  tablet,
  tv,
  printer,
  speaker,
  iot,
  vm,
  unknown,
}

class NetworkDevice {
  final String ip;
  String? hostname;
  String? mdnsName;
  final Set<String> mdnsTypes = {};
  final String? mac;
  final String? vendor;
  int? rttMs;
  bool isGateway;
  bool isSelf;
  bool respondedToProbe;

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
  });

  DeviceType get type => _classify();

  /// Best human-facing name: Bonjour instance name > PTR hostname > vendor.
  String get displayName {
    if (mdnsName != null && mdnsName!.isNotEmpty) return mdnsName!;
    if (hostname != null && hostname!.isNotEmpty) return hostname!;
    if (isGateway) return 'Router';
    if (vendor != null && vendor!.isNotEmpty) return '$vendor device';
    return 'Unknown device';
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

    // Advertised Bonjour services are strong evidence of what a device is.
    for (final t in mdnsTypes) {
      final rule = _mdnsTypeRules[t];
      if (rule != null) return rule;
    }

    // Hostname hints are the strongest signal.
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
