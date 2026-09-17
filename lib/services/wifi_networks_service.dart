import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'oui_db.dart';

/// One nearby BSS from the `getWifiNetworks` scan — public CoreWLAN
/// fields only; the private scanRecord enrichment (real AKM/cipher
/// names, PHY caps, MLO flags) is a planned later pass, see AGENTS.md.
class WifiNetwork {
  final String? ssid; // null → hidden network (or redacted)
  final String? bssid;
  final int? rssi;
  final int? noise;
  final int? channel;
  final String? band;
  final String? width;
  final String security;
  final bool ibss;
  final bool isCurrent;
  String? vendor;

  // -- Private-API enrichment (all optional; public fields are the
  //    baseline and the UI must degrade when these are absent) --------
  final String? securityDetail; // e.g. "WPA2-PSK (CCMP-128)"
  final String? pmf; // "required"/"capable" (+ BIP cipher)
  final String? phyFastest; // "802.11ax"
  final String? phySupported; // "n/ac/ax"
  final double? signalStrength; // normalized 0..1
  final String? channelSpec; // "5g36/80"
  final int? beaconInterval; // TU
  final int? ageMs;
  final int? apMode;
  final int? accessNetworkType;
  final int? rsnPriority;
  final bool wasConnectedDuringSleep;
  final bool filsDiscovery;
  final bool unconfiguredAP;
  final bool fromProbeRsp;
  final bool oweMultiSsid;
  final bool mlo;
  final List<String> tags;
  final List<int> rates; // Mb/s
  final int? channelFlags;
  final int? capabilities;
  final int? secondaryChanOffset;
  final int? vhtCenterChan;
  final String? vhtMaxWidth;
  final int? maxStreams;
  final String? manufacturerName;
  final String? modelName;
  final String? displayName;
  final String? deviceID;
  final String? hessid;
  final String? primaryMAC;
  final String? countryCode;
  final String? friendlyName;
  final int? venueGroup;
  final int? venueType;
  final List<String> operatorFriendlyNames;
  final List<String> venueURLs;
  final List<String> domainNames;
  final List<String> roamingConsortiums;
  final List<String> naiRealms;

  WifiNetwork({
    this.ssid,
    this.bssid,
    this.rssi,
    this.noise,
    this.channel,
    this.band,
    this.width,
    this.security = 'Unknown',
    this.ibss = false,
    this.isCurrent = false,
    this.vendor,
    this.securityDetail,
    this.pmf,
    this.phyFastest,
    this.phySupported,
    this.signalStrength,
    this.channelSpec,
    this.beaconInterval,
    this.ageMs,
    this.apMode,
    this.accessNetworkType,
    this.rsnPriority,
    this.wasConnectedDuringSleep = false,
    this.filsDiscovery = false,
    this.unconfiguredAP = false,
    this.fromProbeRsp = false,
    this.oweMultiSsid = false,
    this.mlo = false,
    this.tags = const [],
    this.rates = const [],
    this.channelFlags,
    this.capabilities,
    this.secondaryChanOffset,
    this.vhtCenterChan,
    this.vhtMaxWidth,
    this.maxStreams,
    this.manufacturerName,
    this.modelName,
    this.displayName,
    this.deviceID,
    this.hessid,
    this.primaryMAC,
    this.countryCode,
    this.friendlyName,
    this.venueGroup,
    this.venueType,
    this.operatorFriendlyNames = const [],
    this.venueURLs = const [],
    this.domainNames = const [],
    this.roamingConsortiums = const [],
    this.naiRealms = const [],
  });

  factory WifiNetwork.fromMap(Map<dynamic, dynamic> m) {
    List<String> strList(String k) =>
        (m[k] as List?)?.map((e) => e.toString()).toList() ?? const [];
    return WifiNetwork(
      ssid: m['ssid'] as String?,
      bssid: m['bssid'] as String?,
      rssi: (m['rssi'] as num?)?.toInt(),
      noise: _plausibleNoise(m['noise']),
      channel: (m['channel'] as num?)?.toInt(),
      band: m['band'] as String?,
      width: m['width'] as String?,
      security: m['security'] as String? ?? 'Unknown',
      ibss: m['ibss'] as bool? ?? false,
      isCurrent: m['isCurrent'] as bool? ?? false,
      securityDetail: m['securityDetail'] as String?,
      pmf: m['pmf'] as String?,
      phyFastest: m['phyFastest'] as String?,
      phySupported: m['phySupported'] as String?,
      signalStrength: (m['signalStrength'] as num?)?.toDouble(),
      channelSpec: m['channelSpec'] as String?,
      beaconInterval: (m['beaconInterval'] as num?)?.toInt(),
      ageMs: (m['ageMs'] as num?)?.toInt(),
      apMode: (m['apMode'] as num?)?.toInt(),
      accessNetworkType: (m['accessNetworkType'] as num?)?.toInt(),
      rsnPriority: (m['rsnPriority'] as num?)?.toInt(),
      wasConnectedDuringSleep: m['wasConnectedDuringSleep'] == true,
      filsDiscovery: m['filsDiscovery'] == true,
      unconfiguredAP: m['unconfiguredAP'] == true,
      fromProbeRsp: m['fromProbeRsp'] == true,
      oweMultiSsid: m['oweMultiSsid'] == true,
      mlo: m['mlo'] == true,
      tags: strList('tags'),
      rates:
          (m['rates'] as List?)?.map((e) => (e as num).toInt()).toList() ??
          const [],
      channelFlags: (m['channelFlags'] as num?)?.toInt(),
      capabilities: (m['capabilities'] as num?)?.toInt(),
      secondaryChanOffset: (m['secondaryChanOffset'] as num?)?.toInt(),
      vhtCenterChan: (m['vhtCenterChan'] as num?)?.toInt(),
      vhtMaxWidth: m['vhtMaxWidth'] as String?,
      maxStreams: (m['maxStreams'] as num?)?.toInt(),
      manufacturerName: m['manufacturerName'] as String?,
      modelName: m['modelName'] as String?,
      displayName: m['displayName'] as String?,
      deviceID: m['deviceID'] as String?,
      hessid: m['hessid'] as String?,
      primaryMAC: m['primaryMAC'] as String?,
      countryCode: m['countryCode'] as String?,
      friendlyName: m['friendlyName'] as String?,
      venueGroup: (m['venueGroup'] as num?)?.toInt(),
      venueType: (m['venueType'] as num?)?.toInt(),
      operatorFriendlyNames: strList('operatorFriendlyNames'),
      venueURLs: strList('venueURLs'),
      domainNames: strList('domainNames'),
      roamingConsortiums: strList('roamingConsortiums'),
      naiRealms: strList('naiRealms'),
    );
  }

  int? get snr => (rssi != null && noise != null) ? rssi! - noise! : null;

  /// noiseMeasurement is 0 for BSSes that never reported a floor —
  /// out-of-range values become null rather than a garbage SNR.
  static int? _plausibleNoise(dynamic v) {
    final n = (v as num?)?.toInt();
    return (n != null && n >= -110 && n <= -20) ? n : null;
  }

  /// 0–4 bars — prefer Apple's normalized signalStrength (private);
  /// fall back to the dBm thresholds the connection tab uses.
  int get bars {
    final s = signalStrength;
    if (s != null) return (s * 4).round().clamp(0, 4);
    final r = rssi;
    if (r == null) return 0;
    if (r >= -50) return 4;
    if (r >= -60) return 3;
    if (r >= -70) return 2;
    if (r >= -80) return 1;
    return 0;
  }
}

/// Periodic Wi-Fi neighbourhood scan. Each scan is a real radio scan
/// (~1-2s inside airportd), so callers pace it — the screen ticks 10s.
class WifiNetworksService extends ChangeNotifier {
  static const _channel = MethodChannel('netnatscan/network');

  List<WifiNetwork> networks = [];
  String? interfaceName;
  bool scanning = false;
  String? error;
  DateTime? lastScanAt;

  bool _disposed = false;

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }

  Future<void> scan() async {
    if (scanning) return;
    scanning = true;
    _notify();
    try {
      await OuiDb.instance.load();
      final res = await _channel.invokeMapMethod<String, dynamic>(
        'getWifiNetworks',
      );
      if (res != null) {
        interfaceName = res['interfaceName'] as String?;
        final list = (res['networks'] as List? ?? const [])
            .whereType<Map>()
            .map(WifiNetwork.fromMap)
            .toList();
        for (final n in list) {
          final b = n.bssid;
          n.vendor = b != null ? OuiDb.instance.lookup(b) : null;
        }
        // Connected network first, then strongest signal.
        list.sort((a, b) {
          if (a.isCurrent != b.isCurrent) return a.isCurrent ? -1 : 1;
          return (b.rssi ?? -999).compareTo(a.rssi ?? -999);
        });
        networks = list;
        error = null;
        lastScanAt = DateTime.now();
      }
    } catch (e) {
      error = 'Wi-Fi scan failed: $e';
    }
    scanning = false;
    _notify();
  }
}
