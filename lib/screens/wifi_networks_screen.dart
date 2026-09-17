import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../services/theme_manager.dart' as theme_manager;
import '../services/wifi_networks_service.dart';
import '../widgets/app_navigation.dart';
import '../widgets/tdesign.dart';
import 'wifi_network_detail_screen.dart';

/// Third tab: nearby Wi-Fi networks from periodic real scans —
/// per-BSS SSID/BSSID/vendor, signal strength, channel/band/width and
/// coarse security. Public CoreWLAN fields only for now.
class WifiNetworksScreen extends StatefulWidget {
  const WifiNetworksScreen({super.key});

  @override
  State<WifiNetworksScreen> createState() => _WifiNetworksScreenState();
}

class _WifiNetworksScreenState extends State<WifiNetworksScreen> {
  final WifiNetworksService _service = WifiNetworksService();
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    _service.scan();
    // Each tick is a real radio scan — keep it sparse.
    _ticker = Timer.periodic(
      const Duration(seconds: 10),
      (_) => _service.scan(),
    );
  }

  @override
  void dispose() {
    _ticker?.cancel();
    _service.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Scaffold(
      backgroundColor: isDark ? Colors.grey.shade900 : Colors.grey.shade50,
      body: SafeArea(
        bottom: false,
        child: Column(
          children: [
            Align(
              alignment: Alignment.centerRight,
              child: Padding(
                padding: const EdgeInsets.only(right: 8, top: 4),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // Wide windows get the theme row in the sidebar;
                    // only the narrow bottom-nav layout needs the toggle.
                    if (!AppNavigation.isDesktop(context))
                      const ThemeCycleButton(),
                    _refreshButton(isDark),
                  ],
                ),
              ),
            ),
            Expanded(
              child: AnimatedBuilder(
                animation: _service,
                builder: (context, _) => _buildBody(isDark),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _refreshButton(bool isDark) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: _service.scanning ? null : () => _service.scan(),
        borderRadius: BorderRadius.circular(8),
        child: Padding(
          padding: const EdgeInsets.all(8),
          child: Icon(
            Icons.refresh,
            color: _service.scanning
                ? (isDark ? Colors.grey.shade700 : Colors.grey.shade300)
                : (isDark ? Colors.white : Colors.black),
            size: 20,
          ),
        ),
      ),
    );
  }

  Widget _buildBody(bool isDark) {
    if (_service.networks.isEmpty && _service.scanning) {
      return const Center(
        child: SizedBox(
          width: 24,
          height: 24,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
      );
    }
    if (_service.networks.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.wifi_off,
              size: 32,
              color: isDark ? Colors.grey.shade700 : Colors.grey.shade300,
            ),
            const SizedBox(height: 12),
            TDText(
              _service.error ?? 'No networks found',
              font: TDTheme.of(context).fontTitleMedium,
              textColor: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
              fontWeight: FontWeight.w600,
            ),
            const SizedBox(height: 4),
            TDText(
              'Scanning needs Wi-Fi on and Location permission.',
              font: TDTheme.of(context).fontBodySmall,
              textColor: isDark ? Colors.grey.shade500 : Colors.grey.shade500,
            ),
          ],
        ),
      );
    }

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        TDText(
          '${_service.networks.length} networks nearby'
          '${_service.lastScanAt != null ? ' · updated ${_fmtTime(_service.lastScanAt!)}' : ''}',
          font: TDTheme.of(context).fontBodySmall,
          textColor: isDark ? Colors.grey.shade500 : Colors.grey.shade500,
        ),
        const SizedBox(height: 8),
        for (final n in _service.networks) _networkCard(n, isDark),
      ],
    );
  }

  Widget _networkCard(WifiNetwork n, bool isDark) {
    final themeColor = theme_manager.ThemeManager().themeColor;
    final titleColor = isDark ? Colors.white : Colors.black;
    final subColor = isDark ? Colors.grey.shade400 : Colors.grey.shade600;
    final name = n.ssid ?? 'Hidden network';

    final line1 = [
      if (n.vendor != null) n.vendor!,
      if (n.channelSpec != null)
        n.channelSpec!
      else ...[
        if (n.channel != null) 'ch ${n.channel}',
        if (n.band != null) n.band!,
        if (n.width != null) n.width!,
      ],
      if (n.snr != null) 'SNR ${n.snr} dB',
    ].join(' · ');
    final line2 = [
      n.securityDetail ?? n.security,
      if (n.ibss) 'Ad-hoc',
      if (n.bssid != null) n.bssid!,
    ].join(' · ');
    final line3 = [
      if (n.phyFastest != null) n.phyFastest!,
      if (n.maxStreams != null && n.maxStreams! > 1) '${n.maxStreams} streams',
      if (n.vhtMaxWidth != null) 'up to ${n.vhtMaxWidth}',
      ...n.tags,
    ].join(' · ');

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: isDark ? Colors.grey.shade800 : Colors.white,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: isDark ? Colors.grey.shade700 : Colors.grey.shade200,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.2 : 0.04),
            offset: const Offset(0, 1),
            blurRadius: 4,
          ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(10),
          onTap: () => Navigator.of(context).push(
            MaterialPageRoute(
              builder: (_) => WifiNetworkDetailScreen(network: n),
            ),
          ),
          onLongPress: () => _copyBssid(n),
          onSecondaryTapUp: (_) => _copyBssid(n),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            child: Row(
              children: [
                Container(
                  width: 36,
                  height: 36,
                  decoration: BoxDecoration(
                    color: isDark
                        ? Colors.blue.shade900.withValues(alpha: 0.3)
                        : Colors.blue.shade50,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(
                    _barsIcon(n.bars),
                    size: 20,
                    color: n.bars > 0
                        ? themeColor
                        : (isDark
                              ? Colors.grey.shade600
                              : Colors.grey.shade400),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Flexible(
                            child: TDText(
                              name,
                              font: TDTheme.of(context).fontBodyMedium,
                              textColor: n.ssid != null ? titleColor : subColor,
                              fontWeight: FontWeight.w600,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          if (n.isCurrent) ...[
                            const SizedBox(width: 6),
                            TDText(
                              'Connected',
                              font: TDTheme.of(context).fontBodySmall,
                              textColor: themeColor,
                              fontWeight: FontWeight.w600,
                            ),
                          ],
                        ],
                      ),
                      if (line1.isNotEmpty)
                        TDText(
                          line1,
                          font: TDTheme.of(context).fontBodySmall,
                          textColor: subColor,
                          overflow: TextOverflow.ellipsis,
                        ),
                      TDText(
                        line2,
                        font: TDTheme.of(context).fontBodySmall,
                        textColor: subColor,
                        overflow: TextOverflow.ellipsis,
                      ),
                      if (line3.isNotEmpty)
                        TDText(
                          line3,
                          font: TDTheme.of(context).fontBodySmall,
                          textColor: themeColor,
                          overflow: TextOverflow.ellipsis,
                        ),
                    ],
                  ),
                ),
                const SizedBox(width: 12),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    TDText(
                      n.rssi != null ? '${n.rssi} dBm' : '—',
                      font: TDTheme.of(context).fontBodyMedium,
                      textColor: titleColor,
                      fontWeight: FontWeight.w600,
                    ),
                    TDText(
                      n.rssiQuality,
                      font: TDTheme.of(context).fontBodySmall,
                      textColor: subColor,
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  void _copyBssid(WifiNetwork n) {
    if (n.bssid == null) return;
    Clipboard.setData(ClipboardData(text: n.bssid!));
    TDToast.showText('BSSID copied', context: context);
  }

  IconData _barsIcon(int bars) => switch (bars) {
    4 => Icons.network_wifi,
    3 => Icons.network_wifi_3_bar,
    2 => Icons.network_wifi_2_bar,
    1 => Icons.network_wifi_1_bar,
    _ => Icons.signal_wifi_0_bar,
  };

  String _fmtTime(DateTime t) {
    final d = t.toLocal();
    String two(int v) => v.toString().padLeft(2, '0');
    return '${two(d.hour)}:${two(d.minute)}:${two(d.second)}';
  }
}
