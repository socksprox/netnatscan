/// wlanapi.dll bindings — the Windows counterpart of the CoreWLAN calls
/// in NetworkPlugin.swift. Two entry points:
///  - [currentConnection] — associated-network facts for the Connection
///    tab (WlanQueryInterface, no radio scan; milliseconds).
///  - [scanNetworks] — nearby BSSes for the Wi-Fi tab (real WlanScan,
///    ~3 s — the caller runs it in a worker isolate).
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:win32/win32.dart';

import 'win32_ffi.dart' as w;

/// Opens a WLAN client handle, runs [body], frees it.
T? _withWlan<T>(T? Function(HANDLE handle, Allocator arena) body) {
  return using((arena) {
    final ver = arena<Uint32>();
    final h = arena<Pointer>();
    if (WlanOpenHandle(2, ver, h) != 0) return null;
    try {
      return body(HANDLE(h.value), arena);
    } finally {
      WlanCloseHandle(HANDLE(h.value));
    }
  });
}

/// WLAN interface (GUID string + description) for [adapterGuid], or the
/// first interface when [adapterGuid] is empty, or null when the machine
/// has no WLAN adapter. The GUID is copied out — the list is freed here.
(String guid, String description)? _findInterface(
    HANDLE handle, Allocator arena, String adapterGuid) {
  final pp = arena<Pointer<WLAN_INTERFACE_INFO_LIST>>();
  if (WlanEnumInterfaces(handle, pp) != 0) return null;
  final list = pp.value;
  try {
    final count = list.ref.dwNumberOfItems;
    for (var i = 0; i < count; i++) {
      final e = list.ref.InterfaceInfo[i];
      final guidStr = e.InterfaceGuid.toString();
      final match = adapterGuid.isEmpty ||
          guidStr.toLowerCase() == adapterGuid.toLowerCase();
      if (match) return (guidStr, e.strInterfaceDescription);
    }
    return null;
  } finally {
    WlanFreeMemory(list);
  }
}

/// Parses a GUID string into a fresh arena allocation.
Pointer<GUID> _guidPtr(Allocator arena, String guid) =>
    arena<GUID>()..ref.setGUID(guid);

// -- labels --------------------------------------------------------------------

String _phyName(int phyType) => switch (phyType) {
      4 => '802.11a', // ofdm
      5 => '802.11b', // hrdsss
      6 => '802.11g', // erp
      7 => '802.11n', // ht
      8 => '802.11ac', // vht
      9 => '802.11ad', // dmg
      10 => '802.11ax', // he
      11 => '802.11be', // eht
      _ => '802.11',
    };

String _phyShort(int phyType) => _phyName(phyType).replaceAll('802.11', '');

/// Coarse security label from the default auth/cipher pair — the
/// Windows equivalent of `networkSecurityLabel` on the macOS side.
String _securityLabel(int auth, int cipher, bool securityEnabled) {
  if (!securityEnabled) return 'Open';
  return switch (auth) {
    DOT11_AUTH_ALGO_80211_OPEN => cipher == DOT11_CIPHER_ALGO_NONE
        ? 'Open'
        : 'WEP',
    DOT11_AUTH_ALGO_80211_SHARED_KEY => 'WEP',
    DOT11_AUTH_ALGO_WPA => 'WPA Enterprise',
    DOT11_AUTH_ALGO_WPA_PSK => 'WPA Personal',
    DOT11_AUTH_ALGO_WPA_NONE => 'WPA',
    DOT11_AUTH_ALGO_RSNA => 'WPA2 Enterprise',
    DOT11_AUTH_ALGO_RSNA_PSK => 'WPA2 Personal',
    DOT11_AUTH_ALGO_WPA3 => 'WPA3 Enterprise 192-bit',
    DOT11_AUTH_ALGO_WPA3_SAE => 'WPA3 Personal',
    DOT11_AUTH_ALGO_OWE => 'OWE',
    DOT11_AUTH_ALGO_WPA3_ENT => 'WPA3 Enterprise',
    _ => 'Unknown',
  };
}

String _akmName(int t) => switch (t) {
      1 => '802.1X',
      2 => 'PSK',
      3 => 'FT-802.1X',
      4 => 'FT-PSK',
      5 => '802.1X-SHA256',
      6 => 'PSK-SHA256',
      7 => 'TDLS',
      8 => 'SAE',
      9 => 'FT-SAE',
      11 => '802.1X-Suite-B',
      12 => '802.1X-Suite-B-192',
      13 => 'FT-802.1X-SHA384',
      14 => 'FILS-SHA256',
      15 => 'FILS-SHA384',
      16 => 'FT-FILS-SHA256',
      17 => 'FT-FILS-SHA384',
      18 => 'OWE',
      24 => 'SAE-EXT',
      _ => 'AKM-$t',
    };

String _cipherName(int t) => switch (t) {
      0 => 'Group',
      1 => 'WEP-40',
      2 => 'TKIP',
      4 => 'CCMP-128',
      5 => 'WEP-104',
      6 => 'BIP-CMAC-128',
      7 => 'None',
      8 => 'GCMP-128',
      9 => 'GCMP-256',
      10 => 'CCMP-256',
      11 => 'BIP-GMAC-128',
      12 => 'BIP-GMAC-256',
      13 => 'BIP-CMAC-256',
      _ => 'Cipher-$t',
    };

// -- beacon/probe IE parsing -----------------------------------------------------

class _Ies {
  String? securityDetail;
  String? pmf;
  int? secondaryChanOffset; // HT IE: 0 none, 1 above, 3 below
  int? vhtChannelWidth; // VHT IE: 0=20/40, 1=80, 2=160, 3=80+80
  int? vhtCenterChan;
  bool hasRsn = false;
  bool hasWpa = false;
}

/// Walks the IE blob of a WLAN_BSS_ENTRY: id/len pairs. Parses RSN (48),
/// WPA vendor (221 + OUI 00:50:F2 type 1), HT capabilities (61) and VHT
/// (192) — enough for the same `securityDetail`/`pmf`/width fields the
/// macOS private scanRecord path produces.
_Ies _parseIes(Uint8List ies) {
  final out = _Ies();
  var i = 0;
  while (i + 2 <= ies.length) {
    final id = ies[i];
    final len = ies[i + 1];
    i += 2 + len;
    if (i > ies.length) break;
    final body = Uint8List.sublistView(ies, i - len, i);
    switch (id) {
      case 48:
        out.hasRsn = true;
        _parseRsn(body, out);
      case 61:
        if (body.length >= 3) out.secondaryChanOffset = body[2] & 3;
      case 192:
        if (body.length >= 3) {
          out.vhtChannelWidth = body[0];
          out.vhtCenterChan = body[2];
        }
      case 221:
        if (body.length >= 6 &&
            body[0] == 0x00 &&
            body[1] == 0x50 &&
            body[2] == 0xf2 &&
            body[3] == 0x01) {
          out.hasWpa = true;
          _parseWpa(Uint8List.sublistView(body, 4), out);
        }
    }
  }
  return out;
}

/// Suite type is the trailing octet of a 4-byte OUI selector.
int _suiteType(Uint8List b, int off) => off + 3 < b.length ? b[off + 3] : -1;

int _u16(Uint8List b, int off) => b[off] | (b[off + 1] << 8);

void _parseRsn(Uint8List b, _Ies out) {
  // version @0..2, group cipher @2..6, pairwise count @6..8.
  if (b.length < 8) return;
  var pos = 6;
  final pairwiseCount = _u16(b, pos);
  pos += 2;
  final uciphers = <int>[
    for (var k = 0; k < pairwiseCount && pos + 4 <= b.length; k++)
      _suiteType(b, pos + 4 * k),
  ];
  pos += 4 * pairwiseCount;
  if (pos + 2 > b.length) return;
  final akmCount = _u16(b, pos);
  pos += 2;
  final akms = <int>[
    for (var k = 0; k < akmCount && pos + 4 <= b.length; k++)
      _suiteType(b, pos + 4 * k),
  ];
  pos += 4 * akmCount;
  int? caps;
  if (pos + 2 <= b.length) {
    caps = _u16(b, pos);
    pos += 2;
  }
  // PMKID list, then optional group-management (BIP) cipher.
  int? bip;
  if (pos + 2 <= b.length) {
    final pmkidCount = _u16(b, pos);
    pos += 2 + 16 * pmkidCount;
    if (pos + 4 <= b.length) bip = _suiteType(b, pos);
  }

  // Same generation logic as describeSecurity() in NetworkPlugin.swift:
  // SAE-family AKM → WPA3, PSK alongside → transition mode.
  final sae = akms.any((t) => const [8, 9, 24].contains(t));
  final psk = akms.any((t) => const [2, 4, 6].contains(t));
  final gen = sae ? (psk ? 'WPA2/WPA3' : 'WPA3') : 'WPA2';
  var s = gen;
  if (akms.isNotEmpty) s += '-${akms.map(_akmName).join('+')}';
  var extra = uciphers.map(_cipherName).join('+');
  if (caps != null) {
    if (caps & 0x80 != 0) {
      out.pmf = 'required';
      extra += '${extra.isEmpty ? '' : ', '}PMF required';
    } else if (caps & 0x40 != 0) {
      out.pmf = 'capable';
      extra += '${extra.isEmpty ? '' : ', '}PMF capable';
    }
  }
  if (bip != null && bip > 0 && out.pmf != null) {
    out.pmf = '${out.pmf} (${_cipherName(bip)})';
  }
  if (extra.isNotEmpty) s += ' ($extra)';
  out.securityDetail = s;
}

void _parseWpa(Uint8List b, _Ies out) {
  // version(2) + group cipher(4) at 0..6.
  if (b.length < 8) return;
  final pairwiseCount = _u16(b, 6);
  var pos = 8;
  final uciphers = <int>[
    for (var k = 0; k < pairwiseCount && pos + 4 <= b.length; k++)
      _suiteType(b, pos + 4 * k),
  ];
  pos += 4 * pairwiseCount;
  if (pos + 2 > b.length) return;
  final akmCount = _u16(b, pos);
  pos += 2;
  final akms = <int>[
    for (var k = 0; k < akmCount && pos + 4 <= b.length; k++)
      _suiteType(b, pos + 4 * k),
  ];
  var s = 'WPA';
  if (akms.isNotEmpty) s += '-${akms.map(_akmName).join('+')}';
  if (uciphers.isNotEmpty) {
    s += ' (${uciphers.map(_cipherName).join('+')})';
  }
  out.securityDetail ??= s;
}

// -- channel helpers ---------------------------------------------------------------

/// ulChCenterFrequency is in kHz → (channel, band).
(int channel, String band) _channelFromFreq(int khz) {
  final mhz = khz / 1000;
  if (mhz < 3000) {
    return (mhz >= 2484 ? 14 : ((mhz - 2407) / 5).round(), '2.4 GHz');
  }
  if (mhz < 5900) return (((mhz - 5000) / 5).round(), '5 GHz');
  return (((mhz - 5950) / 5).round(), '6 GHz');
}

String _bandForChannel(int ch) =>
    ch <= 14 ? '2.4 GHz' : ch <= 220 ? '5 GHz' : '6 GHz';

String? _widthFromIes(_Ies ies) {
  if (ies.vhtChannelWidth != null) {
    return switch (ies.vhtChannelWidth) {
      1 => '80 MHz',
      2 => '160 MHz',
      3 => '80+80 MHz',
      _ => null,
    };
  }
  if (ies.secondaryChanOffset != null && ies.secondaryChanOffset != 0) {
    return '40 MHz';
  }
  return null;
}

/// "5g36/80"-style channel spec — mirrors the csr `channel` description.
String? _channelSpec(int channel, String band, String? width) {
  final prefix = switch (band) {
    '2.4 GHz' => '2g',
    '6 GHz' => '6g',
    _ => '5g',
  };
  final w = width == null ? '' : '/${width.split(' ').first}';
  return '$prefix$channel$w';
}

// -- current connection ---------------------------------------------------------

/// WLAN_CONNECTION_ATTRIBUTES for the adapter whose GUID string is
/// [adapterGuid] ("{...}" from GetAdaptersAddresses). Returns null when
/// the interface isn't a WLAN one or the query fails.
Map<String, Object?>? currentConnection(String adapterGuid, String ifName,
    {String? mac}) {
  return _withWlan((handle, arena) {
    final info = _findInterface(handle, arena, adapterGuid);
    if (info == null) return null;
    final guid = _guidPtr(arena, info.$1);

    final size = arena<Uint32>();
    final pp = arena<Pointer>();
    final r = WlanQueryInterface(handle, guid,
        wlan_intf_opcode_current_connection, size, pp, nullptr);
    if (r != 0) return null;
    try {
      final c = pp.value.cast<WLAN_CONNECTION_ATTRIBUTES>().ref;
      final assoc = c.wlanAssociationAttributes;
      final sec = c.wlanSecurityAttributes;
      final m = <String, Object?>{
        'interfaceName': ifName,
        'ssidAvailable': c.isState == wlan_interface_state_connected,
        'security': _securityLabel(
            sec.dot11AuthAlgorithm, sec.dot11CipherAlgorithm,
            sec.bSecurityEnabled),
        'mac': ?mac,
      };
      if (c.isState != wlan_interface_state_connected) return m;

      final ssidBytes = <int>[
        for (var i = 0; i < assoc.dot11Ssid.uSSIDLength; i++)
          assoc.dot11Ssid.ucSSID[i],
      ];
      if (ssidBytes.isNotEmpty) {
        m['ssid'] = utf8.decode(ssidBytes, allowMalformed: true);
      }
      m['bssid'] = w.macStringFromBytes(
          [for (var i = 0; i < 6; i++) assoc.dot11Bssid[i]]);
      final quality = assoc.wlanSignalQuality;
      m['signalStrength'] = quality / 100;
      m['rssi'] = (quality / 2 - 100).round();
      m['transmitRate'] = assoc.ulTxRate / 1000; // kbps → Mbps
      m['phyMode'] = _phyName(assoc.dot11PhyType);
      m['securityDetail'] = _securityDetail(
          sec.dot11AuthAlgorithm, sec.dot11CipherAlgorithm);

      // wlan_intf_opcode_channel_number — a plain ULONG, cheap.
      final chSize = arena<Uint32>();
      final chPtr = arena<Pointer>();
      if (WlanQueryInterface(
              handle, guid, WLAN_INTF_OPCODE(8), chSize, chPtr, nullptr) ==
          0) {
        try {
          final ch = chPtr.value.cast<Uint32>().value;
          m['channel'] = ch;
          m['channelBand'] = _bandForChannel(ch);
        } finally {
          WlanFreeMemory(chPtr.value);
        }
      }
      return m;
    } finally {
      WlanFreeMemory(pp.value);
    }
  });
}

/// "WPA2-PSK (CCMP-128)"-style detail from the connection's default
/// auth/cipher pair.
String? _securityDetail(int auth, int cipher) {
  final akm = switch (auth) {
    DOT11_AUTH_ALGO_WPA || DOT11_AUTH_ALGO_RSNA => '802.1X',
    DOT11_AUTH_ALGO_WPA_PSK || DOT11_AUTH_ALGO_RSNA_PSK => 'PSK',
    DOT11_AUTH_ALGO_WPA3 || DOT11_AUTH_ALGO_WPA3_ENT => '802.1X-Suite-B',
    DOT11_AUTH_ALGO_WPA3_SAE => 'SAE',
    _ => null,
  };
  if (akm == null) return null;
  final gen = switch (auth) {
    DOT11_AUTH_ALGO_WPA || DOT11_AUTH_ALGO_WPA_PSK => 'WPA',
    DOT11_AUTH_ALGO_WPA3 ||
    DOT11_AUTH_ALGO_WPA3_SAE ||
    DOT11_AUTH_ALGO_WPA3_ENT =>
      'WPA3',
    _ => 'WPA2',
  };
  final c = switch (cipher) {
    DOT11_CIPHER_ALGO_WEP40 => 'WEP-40',
    DOT11_CIPHER_ALGO_TKIP => 'TKIP',
    DOT11_CIPHER_ALGO_CCMP => 'CCMP-128',
    DOT11_CIPHER_ALGO_WEP104 => 'WEP-104',
    DOT11_CIPHER_ALGO_BIP => 'BIP-CMAC-128',
    DOT11_CIPHER_ALGO_GCMP => 'GCMP-128',
    DOT11_CIPHER_ALGO_GCMP_256 => 'GCMP-256',
    DOT11_CIPHER_ALGO_CCMP_256 => 'CCMP-256',
    _ => null,
  };
  return '$gen-$akm${c != null ? ' ($c)' : ''}';
}

// -- scan -----------------------------------------------------------------------

/// Nearby BSSes — the `getWifiNetworks` payload. Runs in a worker
/// isolate (WlanScan blocks for seconds).
Map<String, Object?> scanNetworks() {
  final result = _withWlan((handle, arena) {
    final info = _findInterface(handle, arena, '');
    if (info == null) return <String, Object?>{'networks': <Object?>[]};
    final guid = _guidPtr(arena, info.$1);

    // Kick off a radio scan, then poll the BSS list until it stabilizes
    // or ~5 s pass (a first poll often already shows partial results).
    WlanScan(handle, guid, nullptr, nullptr);
    Pointer<WLAN_BSS_LIST> bss = nullptr;
    var lastCount = -1;
    for (var i = 0; i < 12; i++) {
      w.sleepMs(i == 0 ? 1500 : 500);
      final pp = arena<Pointer<WLAN_BSS_LIST>>();
      if (WlanGetNetworkBssList(
              handle, guid, nullptr, dot11_BSS_type_any, false, pp) ==
          0) {
        if (bss != nullptr) WlanFreeMemory(bss);
        bss = pp.value;
        final n = bss.ref.dwNumberOfItems;
        if (n > 0 && n == lastCount && i >= 4) break;
        lastCount = n;
      }
    }

    // Available-network list carries the default auth/cipher pair and
    // the connected flag — merged by SSID below. Scalars are copied out:
    // the backing list is freed before the BSS entries are processed.
    final netsBySsid =
        <String, (int auth, int cipher, bool secured, Set<int> phys)>{};
    final ppAvail = arena<Pointer<WLAN_AVAILABLE_NETWORK_LIST>>();
    if (WlanGetAvailableNetworkList(handle, guid, 0, ppAvail) == 0) {
      final list = ppAvail.value;
      try {
        final n = list.ref.dwNumberOfItems;
        for (var i = 0; i < n; i++) {
          final net = list.ref.Network[i];
          final ssid = _ssidString(net.dot11Ssid);
          if (ssid.isEmpty) continue;
          netsBySsid[ssid] = (
            net.dot11DefaultAuthAlgorithm,
            net.dot11DefaultCipherAlgorithm,
            net.bSecurityEnabled,
            {
              for (var k = 0; k < net.uNumberOfPhyTypes && k < 8; k++)
                net.dot11PhyTypes[k],
            },
          );
        }
      } finally {
        WlanFreeMemory(list);
      }
    }

    // Current connection BSSID for the isCurrent flag.
    String? currentBssid;
    final cSize = arena<Uint32>();
    final cPtr = arena<Pointer>();
    if (WlanQueryInterface(handle, guid,
            wlan_intf_opcode_current_connection, cSize, cPtr, nullptr) ==
        0) {
      try {
        final c = cPtr.value.cast<WLAN_CONNECTION_ATTRIBUTES>().ref;
        if (c.isState == wlan_interface_state_connected) {
          currentBssid = w.macStringFromBytes([
            for (var i = 0; i < 6; i++)
              c.wlanAssociationAttributes.dot11Bssid[i]
          ]);
        }
      } finally {
        WlanFreeMemory(cPtr.value);
      }
    }

    final networks = <Map<String, Object?>>[];
    if (bss != nullptr) {
      try {
        final count = bss.ref.dwNumberOfItems;
        for (var i = 0; i < count; i++) {
          final e = bss.ref.wlanBssEntries[i];
          networks.add(_bssToMap(e, bss, netsBySsid, currentBssid));
        }
      } finally {
        WlanFreeMemory(bss);
      }
    }
    return <String, Object?>{
      'interfaceName': info.$2,
      'networks': networks,
    };
  });
  return result ?? {'networks': <Object?>[]};
}

String _ssidString(DOT11_SSID s) {
  final bytes = <int>[for (var i = 0; i < s.uSSIDLength; i++) s.ucSSID[i]];
  return utf8.decode(bytes, allowMalformed: true);
}

Map<String, Object?> _bssToMap(
    WLAN_BSS_ENTRY e,
    Pointer<WLAN_BSS_LIST> base,
    Map<String, (int, int, bool, Set<int>)> netsBySsid,
    String? currentBssid) {
  final ssid = _ssidString(e.dot11Ssid);
  final bssid =
      w.macStringFromBytes([for (var i = 0; i < 6; i++) e.dot11Bssid[i]]);
  final (channel, band) = _channelFromFreq(e.ulChCenterFrequency);
  final ies = e.ulIeSize > 0
      ? _parseIes(
          (base.cast<Uint8>() + e.ulIeOffset).asTypedList(e.ulIeSize))
      : _Ies();

  final net = netsBySsid[ssid];
  final security = net != null
      ? _securityLabel(net.$1, net.$2, net.$3)
      : (ies.hasRsn
          ? 'WPA2/WPA3'
          : ies.hasWpa
              ? 'WPA'
              : (e.usCapabilityInformation & 0x10 != 0 ? 'WEP' : 'Open'));

  // PHY generations: the BSS's own phy plus the network's phy list.
  final phys = <int>{e.dot11BssPhyType, ...?net?.$4};
  const phyOrder = [9, 4, 5, 6, 7, 8, 10, 11]; // ad,a,b,g,n,ac,ax,be
  final sortedPhys = phys.where((p) => p > 0).toList()
    ..sort((a, b) {
      final ia = phyOrder.indexOf(a);
      final ib = phyOrder.indexOf(b);
      return (ia < 0 ? 99 : ia).compareTo(ib < 0 ? 99 : ib);
    });
  final phySupported = sortedPhys.map(_phyShort).join('/');
  final phyFastest = sortedPhys.isEmpty ? null : _phyName(sortedPhys.last);

  final width = _widthFromIes(ies);
  final rates = <int>[
    for (var i = 0; i < e.wlanRateSet.uRateSetLength && i < 126; i++)
      ((e.wlanRateSet.usRateSet[i] & 0x7fff) / 2).round(),
  ];

  return {
    'ssid': ssid.isEmpty ? null : ssid,
    'bssid': bssid,
    'rssi': e.lRssi,
    'channel': channel,
    'band': band,
    'width': ?width,
    'security': security,
    'ibss': e.dot11BssType == dot11_BSS_type_independent,
    'isCurrent': currentBssid != null &&
        bssid.toLowerCase() == currentBssid.toLowerCase(),
    'securityDetail': ?ies.securityDetail,
    'pmf': ?ies.pmf,
    'phyFastest': ?phyFastest,
    if (phySupported.isNotEmpty) 'phySupported': phySupported,
    'signalStrength': e.uLinkQuality / 100,
    'channelSpec': _channelSpec(channel, band, width),
    'beaconInterval': e.usBeaconPeriod,
    'capabilities': e.usCapabilityInformation,
    if (ies.secondaryChanOffset != null)
      'secondaryChanOffset': ies.secondaryChanOffset,
    if (ies.vhtCenterChan != null && ies.vhtCenterChan != 0)
      'vhtCenterChan': ies.vhtCenterChan,
    if (ies.vhtChannelWidth != null)
      'vhtMaxWidth': switch (ies.vhtChannelWidth) {
        2 => '160 MHz',
        3 => '160/80+80 MHz',
        _ => null,
      },
    if (rates.isNotEmpty) 'rates': rates,
  };
}
