import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

/// MAC vendor lookup backed by the bundled OUI database
/// (`assets/oui.min.json.gz`, sourced from the netscli project).
class OuiDb {
  OuiDb._();
  static final OuiDb instance = OuiDb._();

  Map<String, String>? _map;

  Future<void> load() async {
    if (_map != null) return;
    final data = await rootBundle.load('assets/oui.min.json.gz');
    final jsonText = utf8.decode(gzip.decode(data.buffer.asUint8List()));
    final decoded = json.decode(jsonText);
    final map = <String, String>{};
    if (decoded is Map) {
      decoded.forEach((key, value) {
        final prefix = _normalizePrefix(key.toString());
        if (prefix != null && value is String) {
          map[prefix] = value;
        }
      });
    }
    _map = map;
  }

  String? lookup(String? mac) {
    final prefix = mac == null ? null : _normalizePrefix(mac);
    if (prefix == null) return null;
    final raw = _map?[prefix];
    return raw == null ? null : prettyVendor(raw);
  }

  /// IEEE OUI names come as e.g. `TP-LINK TECHNOLOGIES CO.,LTD.` — strip the
  /// corporate suffixes and title-case for display.
  static String prettyVendor(String raw) {
    var v = raw.trim();
    // Drop corporate suffixes, possibly chained ("CO.,LTD.", "GMBH", ...).
    final suffix = RegExp(
      r'[\s,]+(co\.?,?\s*ltd\.?|inc\.?|gmbh|corp\.?|corporation|limited|ltd\.?|llc|s\.?a\.?|b\.?v\.?|a\.?g\.?|company|co\.?|technologies|technology|electronics|electronic|group)\.?$',
      caseSensitive: false,
    );
    var prev = '';
    while (v != prev) {
      prev = v;
      v = v.replaceAll(suffix, '').trim();
    }
    if (v.isEmpty) v = raw.trim();
    if (v == v.toUpperCase()) {
      v = v.split(' ').map(_titleWord).join(' ');
    }
    return v;
  }

  static String _titleWord(String word) {
    return word
        .split('-')
        .map(
          (seg) =>
              seg.length <= 3 ? seg : seg[0] + seg.substring(1).toLowerCase(),
        )
        .join('-');
  }

  static String? _normalizePrefix(String mac) {
    final hex = mac
        .replaceAll(':', '')
        .replaceAll('-', '')
        .replaceAll('.', '')
        .toUpperCase();
    if (hex.length < 6) return null;
    final prefix = hex.substring(0, 6);
    return RegExp(r'^[0-9A-F]{6}$').hasMatch(prefix) ? prefix : null;
  }
}
