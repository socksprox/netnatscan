import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../services/theme_manager.dart' as theme_manager;
import '../services/wifi_networks_service.dart';
import '../widgets/custom_app_bar.dart';
import '../widgets/signal_quality_meter.dart';
import '../widgets/tdesign.dart';

/// Everything one scan learned about a single BSS — public fields plus
/// the private CWFScanResult/scanRecord enrichment. Sections simply
/// omit whatever the private surface didn't provide.
class WifiNetworkDetailScreen extends StatelessWidget {
  final WifiNetwork network;

  const WifiNetworkDetailScreen({super.key, required this.network});

  @override
  Widget build(BuildContext context) {
    final n = network;
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final themeColor = theme_manager.ThemeManager().themeColor;
    final name = n.ssid ?? 'Hidden network';
    return Scaffold(
      backgroundColor: isDark ? Colors.grey.shade900 : Colors.grey.shade50,
      appBar: CustomAppBar(title: name),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _header(context, n, isDark, themeColor),
          const SizedBox(height: 16),
          _group(context, isDark, 'Network', [
            ('SSID', name),
            if (n.bssid != null) ('BSSID', n.bssid!),
            if (n.vendor != null) ('Vendor', n.vendor!),
            if (n.hessid != null) ('HESSID', n.hessid!),
            if (n.primaryMAC != null) ('Primary MAC', n.primaryMAC!),
            if (n.channelSpec != null)
              ('Channel', n.channelSpec!)
            else if (n.channel != null)
              (
                'Channel',
                [
                  '${n.channel}',
                  if (n.band != null) n.band!,
                  if (n.width != null) n.width!,
                ].join(' · '),
              ),
            if (n.secondaryChanOffset != null)
              (
                'Secondary ch. offset',
                switch (n.secondaryChanOffset) {
                  0 => 'none (20 MHz)',
                  1 => 'above primary',
                  3 => 'below primary',
                  _ => '${n.secondaryChanOffset}',
                },
              ),
            if (n.vhtCenterChan != null)
              ('VHT center channel', '${n.vhtCenterChan}'),
            if (n.channelFlags != null)
              ('Channel flags', _channelFlagString(n.channelFlags!)),
            if (n.beaconInterval != null)
              ('Beacon interval', '${n.beaconInterval} TU'),
            if (n.ageMs != null) ('Beacon age', _fmtAge(n.ageMs!)),
            ('From probe response', n.fromProbeRsp ? 'Yes' : 'No'),
            if (n.accessNetworkType != null && n.accessNetworkType != 0)
              ('Access network', _accessNetworkString(n.accessNetworkType!)),
            ('Ad-hoc (IBSS)', n.ibss ? 'Yes' : 'No'),
            ('Connected', n.isCurrent ? 'Yes' : 'No'),
            if (n.wasConnectedDuringSleep) ('Connected during sleep', 'Yes'),
          ]),
          _group(
            context,
            isDark,
            'Signal',
            [
              if (n.rssi != null)
                ('Signal quality', signalQualityLabel(n.rssi, n.noise)),
              if (n.signalStrength != null)
                (
                  'Signal strength',
                  '${(n.signalStrength! * 100).toStringAsFixed(0)}%',
                ),
              if (n.phyFastest != null) ('Fastest PHY', n.phyFastest!),
              if (n.phySupported != null)
                ('Supported PHY modes', n.phySupported!),
              if (n.maxStreams != null)
                ('Spatial streams', 'up to ${n.maxStreams}'),
              if (n.vhtMaxWidth != null) ('VHT max width', n.vhtMaxWidth!),
              if (n.rates.isNotEmpty)
                ('Basic rates', '${n.rates.join(', ')} Mb/s'),
            ],
            footer: n.rssi != null
                ? Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: SignalQualityMeter(rssi: n.rssi!, noise: n.noise),
                  )
                : null,
          ),
          _group(context, isDark, 'Security', [
            ('Security', n.securityDetail ?? n.security),
            if (n.securityDetail != null) ('Coarse (public API)', n.security),
            if (n.pmf != null) ('PMF (802.11w)', n.pmf!),
            if (n.capabilities != null)
              ('Capabilities', _capabilityString(n.capabilities!)),
            if (n.oweMultiSsid) ('OWE transition', 'Multi-SSID'),
          ]),
          if (n.tags.isNotEmpty || n.mlo || n.filsDiscovery || n.unconfiguredAP)
            _group(context, isDark, 'Features', [
              if (n.tags.isNotEmpty) ('Tags', n.tags.join(', ')),
              if (n.mlo) ('Multi-Link Operation', 'Yes'),
              if (n.filsDiscovery) ('FILS discovery', 'Yes'),
              if (n.unconfiguredAP) ('Unconfigured AP', 'Yes'),
            ]),
          if (_hasIdentity(n))
            _group(context, isDark, 'Identity & Venue', [
              if (n.manufacturerName != null)
                ('Manufacturer', n.manufacturerName!),
              if (n.modelName != null) ('Model', n.modelName!),
              if (n.displayName != null) ('Display name', n.displayName!),
              if (n.friendlyName != null) ('Friendly name', n.friendlyName!),
              if (n.deviceID != null) ('Device ID', n.deviceID!),
              if (n.countryCode != null)
                ('Country code', '${n.countryCode!} (this router)'),
              if (n.venueGroup != null) ('Venue group', '${n.venueGroup}'),
              if (n.venueType != null) ('Venue type', '${n.venueType}'),
              if (n.operatorFriendlyNames.isNotEmpty)
                ('Operator', n.operatorFriendlyNames.join(', ')),
              if (n.domainNames.isNotEmpty)
                ('Domains', n.domainNames.join(', ')),
              if (n.roamingConsortiums.isNotEmpty)
                ('Roaming consortium', n.roamingConsortiums.join(', ')),
              if (n.naiRealms.isNotEmpty)
                ('NAI realms', n.naiRealms.join(', ')),
              if (n.venueURLs.isNotEmpty)
                ('Venue URLs', n.venueURLs.join('\n')),
            ]),
          const SizedBox(height: 8),
        ],
      ),
    );
  }

  bool _hasIdentity(WifiNetwork n) =>
      n.manufacturerName != null ||
      n.modelName != null ||
      n.displayName != null ||
      n.friendlyName != null ||
      n.deviceID != null ||
      n.countryCode != null ||
      n.venueGroup != null ||
      n.venueType != null ||
      n.operatorFriendlyNames.isNotEmpty ||
      n.domainNames.isNotEmpty ||
      n.roamingConsortiums.isNotEmpty ||
      n.naiRealms.isNotEmpty ||
      n.venueURLs.isNotEmpty;

  Widget _header(
    BuildContext context,
    WifiNetwork n,
    bool isDark,
    Color themeColor,
  ) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: _cardDecoration(isDark),
      child: Row(
        children: [
          Container(
            width: 44,
            height: 44,
            decoration: BoxDecoration(
              color: isDark
                  ? Colors.blue.shade900.withValues(alpha: 0.3)
                  : Colors.blue.shade50,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(
              switch (n.bars) {
                4 => Icons.network_wifi,
                3 => Icons.network_wifi_3_bar,
                2 => Icons.network_wifi_2_bar,
                1 => Icons.network_wifi_1_bar,
                _ => Icons.signal_wifi_0_bar,
              },
              size: 24,
              color: themeColor,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                TDText(
                  n.ssid ?? 'Hidden network',
                  font: TDTheme.of(context).fontTitleMedium,
                  textColor: isDark ? Colors.white : Colors.black,
                  fontWeight: FontWeight.w600,
                ),
                const SizedBox(height: 2),
                TDText(
                  [
                    if (n.isCurrent) 'Connected',
                    if (n.rssi != null) '${n.rssi} dBm',
                    n.securityDetail ?? n.security,
                  ].join(' · '),
                  font: TDTheme.of(context).fontBodySmall,
                  textColor: isDark
                      ? Colors.grey.shade400
                      : Colors.grey.shade600,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  /// A section card of copyable key/value rows (null entries dropped),
  /// with an optional non-row widget appended inside the card.
  Widget _group(
    BuildContext context,
    bool isDark,
    String title,
    List<(String, String)?> rows, {
    Widget? footer,
  }) {
    final items = rows.whereType<(String, String)>().toList();
    if (items.isEmpty && footer == null) return const SizedBox.shrink();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        TDText(
          title,
          font: TDTheme.of(context).fontTitleMedium,
          textColor: isDark ? Colors.white : Colors.black,
          fontWeight: FontWeight.w600,
        ),
        const SizedBox(height: 8),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: _cardDecoration(isDark),
          child: Column(
            children: [
              for (var i = 0; i < items.length; i++)
                _row(
                  context,
                  items[i].$1,
                  items[i].$2,
                  isDark,
                  last: i == items.length - 1 && footer == null,
                ),
              ?footer,
            ],
          ),
        ),
        const SizedBox(height: 16),
      ],
    );
  }

  Widget _row(
    BuildContext context,
    String label,
    String value,
    bool isDark, {
    bool last = false,
  }) {
    return GestureDetector(
      behavior: HitTestBehavior.opaque,
      onLongPress: () => _copyField(context, label, value),
      onSecondaryTapUp: (_) => _copyField(context, label, value),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 6),
        child: Column(
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SizedBox(
                  width: 150,
                  child: TDText(
                    label,
                    font: TDTheme.of(context).fontBodySmall,
                    textColor: isDark
                        ? Colors.grey.shade400
                        : Colors.grey.shade600,
                  ),
                ),
                Expanded(
                  child: TDText(
                    value,
                    font: TDTheme.of(context).fontBodyMedium,
                    textColor: isDark ? Colors.white : Colors.black87,
                    fontWeight: FontWeight.w600,
                    textAlign: TextAlign.right,
                  ),
                ),
              ],
            ),
            if (!last) ...[
              const SizedBox(height: 6),
              Divider(
                height: 1,
                color: isDark ? Colors.grey.shade700 : Colors.grey.shade200,
              ),
            ],
          ],
        ),
      ),
    );
  }

  void _copyField(BuildContext context, String label, String value) {
    Clipboard.setData(ClipboardData(text: value));
    TDToast.showText('$label copied', context: context);
  }

  BoxDecoration _cardDecoration(bool isDark) => BoxDecoration(
    color: isDark ? Colors.grey.shade800 : Colors.white,
    borderRadius: BorderRadius.circular(10),
    border: Border.all(
      color: isDark ? Colors.grey.shade700 : Colors.grey.shade200,
    ),
    boxShadow: [
      BoxShadow(
        color: Colors.black.withValues(alpha: isDark ? 0.2 : 0.03),
        offset: const Offset(0, 1),
        blurRadius: 3,
      ),
    ],
  );

  /// 802.11 Capability Information field → readable bit names.
  String _capabilityString(int caps) {
    const bits = {
      0: 'ESS',
      1: 'IBSS',
      2: 'CF-Pollable',
      3: 'CF-Poll Request',
      4: 'Privacy',
      5: 'Short preamble',
      6: 'PBCC',
      7: 'Channel agility',
      8: 'Spectrum mgmt',
      9: 'QoS',
      10: 'Short slot',
      11: 'APSD',
      12: 'Radio measurement',
      13: 'DSSS-OFDM',
      14: 'Delayed Block Ack',
      15: 'Immediate Block Ack',
    };
    final names = [
      for (final e in bits.entries)
        if (caps & (1 << e.key) != 0) e.value,
    ];
    return names.isEmpty ? 'None' : names.join(' · ');
  }

  String _fmtAge(int ms) {
    final s = ms ~/ 1000;
    if (s < 60) return '${s}s ago';
    if (s < 3600) return '${s ~/ 60}m ago';
    return '${(s / 3600).toStringAsFixed(1)}h ago';
  }

  /// apple80211_channel_flag (apple80211_var.h).
  String _channelFlagString(int flags) {
    const bits = {
      0x1: '10 MHz',
      0x2: '20 MHz',
      0x4: '40 MHz',
      0x8: '2.4 GHz',
      0x10: '5 GHz',
      0x20: 'IBSS',
      0x40: 'Host AP',
      0x80: 'Active scan',
      0x100: 'DFS',
      0x200: 'Ext. above',
      0x400: '80 MHz',
      0x800: '160 MHz',
    };
    final names = [
      for (final e in bits.entries)
        if (flags & e.key != 0) e.value,
    ];
    return names.isEmpty ? 'None' : names.join(' · ');
  }

  /// 802.11u ANQP access-network-type.
  String _accessNetworkString(int type) {
    switch (type) {
      case 1:
        return 'Private with guest access';
      case 2:
        return 'Chargeable public';
      case 3:
        return 'Free public';
      case 4:
        return 'Personal device';
      case 5:
        return 'Emergency services';
      case 14:
        return 'Test';
      case 15:
        return 'Wildcard';
      default:
        return 'Type $type';
    }
  }
}
