import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

/// The last identity a device volunteered over mDNS, remembered across
/// scans so sleeping devices (which keep their ARP entry via the Wi-Fi
/// chip but stop answering Bonjour) still show their real name.
class CachedDevice {
  String name;
  Set<String> mdnsTypes;
  DateTime lastSeen;

  CachedDevice({
    required this.name,
    required this.mdnsTypes,
    required this.lastSeen,
  });
}

/// Persists MAC → device identity to `device_names.json` in the app
/// documents directory. Keyed by MAC (not IP) since DHCP reassigns
/// addresses while iOS/macOS private MACs stay stable per network.
class DeviceNameCache {
  static final DeviceNameCache instance = DeviceNameCache._();
  DeviceNameCache._();

  static const _maxAge = Duration(days: 90);

  final Map<String, CachedDevice> _byMac = {};
  bool _loaded = false;

  Future<void> load() async {
    if (_loaded) return;
    _loaded = true;
    try {
      final directory = await getApplicationDocumentsDirectory();
      final file = File('${directory.path}/device_names.json');
      if (!await file.exists()) return;
      final raw = jsonDecode(await file.readAsString());
      if (raw is! Map) return;
      final cutoff = DateTime.now().subtract(_maxAge);
      for (final e in raw.entries) {
        final v = e.value;
        if (v is! Map) continue;
        final name = v['name'] as String?;
        final seen = DateTime.tryParse(v['seen'] as String? ?? '');
        if (name == null || name.isEmpty || seen == null) continue;
        if (seen.isBefore(cutoff)) continue;
        _byMac[e.key as String] = CachedDevice(
          name: name,
          mdnsTypes: {for (final t in (v['types'] as List? ?? const [])) '$t'},
          lastSeen: seen,
        );
      }
    } catch (e) {
      debugPrint('Error loading device name cache: $e');
    }
  }

  CachedDevice? lookup(String? mac) =>
      mac == null ? null : _byMac[mac.toLowerCase()];

  void update(String mac, String name, Set<String> mdnsTypes) {
    _byMac[mac.toLowerCase()] = CachedDevice(
      name: name,
      mdnsTypes: {...mdnsTypes},
      lastSeen: DateTime.now(),
    );
  }

  Future<void> save() async {
    try {
      final directory = await getApplicationDocumentsDirectory();
      final file = File('${directory.path}/device_names.json');
      final raw = {
        for (final e in _byMac.entries)
          e.key: {
            'name': e.value.name,
            'types': e.value.mdnsTypes.toList(),
            'seen': e.value.lastSeen.toIso8601String(),
          },
      };
      await file.writeAsString(jsonEncode(raw));
    } catch (e) {
      debugPrint('Error saving device name cache: $e');
    }
  }
}
