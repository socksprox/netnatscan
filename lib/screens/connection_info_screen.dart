import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../services/connection_info_service.dart';
import '../services/network_scanner.dart';
import '../services/theme_manager.dart' as theme_manager;
import '../widgets/app_navigation.dart';
import '../widgets/signal_quality_meter.dart';
import '../widgets/tdesign.dart';

/// Second tab: everything knowable about the current uplink —
/// Wi-Fi radio facts, addressing, DNS/proxy/DHCP, per-interface
/// counters since boot (with a live rate), plus public IP.
class ConnectionInfoScreen extends StatefulWidget {
  const ConnectionInfoScreen({super.key});

  @override
  State<ConnectionInfoScreen> createState() => _ConnectionInfoScreenState();
}

class _ConnectionInfoScreenState extends State<ConnectionInfoScreen> {
  final ConnectionInfoService _service = ConnectionInfoService();
  Timer? _ticker;

  @override
  void initState() {
    super.initState();
    _service.reload();
    // Cheap sysctl refresh — drives the live throughput readout.
    _ticker = Timer.periodic(
      const Duration(seconds: 2),
      (_) => _service.refreshStats(),
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
        onTap: _service.loading ? null : () => _service.reload(),
        borderRadius: BorderRadius.circular(8),
        child: Padding(
          padding: const EdgeInsets.all(8),
          child: Icon(
            Icons.refresh,
            color: _service.loading
                ? (isDark ? Colors.grey.shade700 : Colors.grey.shade300)
                : (isDark ? Colors.white : Colors.black),
            size: 20,
          ),
        ),
      ),
    );
  }

  Widget _buildBody(bool isDark) {
    final info = _service.info;
    if (info == null && _service.error == null) {
      return const Center(
        child: SizedBox(
          width: 24,
          height: 24,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
      );
    }
    if (info == null) {
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
              _service.error ?? 'No connection info',
              font: TDTheme.of(context).fontTitleMedium,
              textColor: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
              fontWeight: FontWeight.w600,
            ),
          ],
        ),
      );
    }

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        _connectionCard(info, isDark),
        const SizedBox(height: 12),
        _addressingCard(info, isDark),
        const SizedBox(height: 12),
        _dnsCard(info, isDark),
        const SizedBox(height: 12),
        _trafficCard(info, isDark),
        const SizedBox(height: 12),
        _interfacesCard(info, isDark),
        const SizedBox(height: 12),
        _systemCard(info, isDark),
        const SizedBox(height: 8),
      ],
    );
  }

  // --- Sections -----------------------------------------------------------

  Widget _connectionCard(ConnectionInfo info, bool isDark) {
    final wifi = info.wifi;
    final typeLabel = switch (info.networkType) {
      'wifi' => 'Wi-Fi',
      'ethernet' => 'Ethernet',
      'loopback' => 'Loopback',
      'other' => 'Other',
      _ => 'Offline',
    };
    final typeIcon = switch (info.networkType) {
      'wifi' => Icons.wifi,
      'ethernet' => Icons.settings_ethernet,
      _ => Icons.wifi_off,
    };

    return _section(
      icon: typeIcon,
      title: 'Connection',
      isDark: isDark,
      rows: [
        _row('Type', typeLabel, isDark),
        _row('Interface', info.primaryInterface ?? '—', isDark),
        if (wifi != null) ...[
          _row(
            'SSID',
            wifi.ssid ??
                (wifi.ssidAvailable
                    ? '—'
                    : 'Hidden (needs Location permission)'),
            isDark,
          ),
          _row('Security', wifi.securityDetail ?? wifi.security ?? '—', isDark),
          _row('BSSID', wifi.bssid ?? '—', isDark),
          _row(
            'Channel',
            [
              if (wifi.channel != null) '${wifi.channel}',
              if (wifi.channelBand != null) wifi.channelBand!,
              if (wifi.channelWidth != null) wifi.channelWidth!,
            ].join(' · '),
            isDark,
          ),
          _row('PHY mode', wifi.phyMode ?? '—', isDark),
          if (wifi.rssi != null) ...[
            _row(
              'Signal quality',
              signalQualityLabel(wifi.rssi, wifi.noise),
              isDark,
            ),
            Padding(
              padding: const EdgeInsets.only(top: 4, bottom: 8),
              child: SignalQualityMeter(rssi: wifi.rssi!, noise: wifi.noise),
            ),
          ],
          _row(
            'Transmit rate',
            wifi.transmitRate != null
                ? '${wifi.transmitRate!.toStringAsFixed(0)} Mb/s'
                : '—',
            isDark,
          ),
          if (wifi.countryCode != null)
            _row('Country code', '${wifi.countryCode!} (this device)', isDark),
        ],
      ],
    );
  }

  Widget _addressingCard(ConnectionInfo info, bool isDark) {
    final iface = _primaryInterfaceInfo();
    final stats = info.primaryStats;
    final dhcp = info.dhcp;

    return _section(
      icon: Icons.router_outlined,
      title: 'Addressing',
      isDark: isDark,
      rows: [
        _row('IPv4 address', iface?.ip ?? '—', isDark),
        _row('Subnet mask', iface?.netmask ?? '—', isDark),
        _row('Network', iface?.cidr ?? '—', isDark),
        _row('MAC address', iface?.mac ?? stats?.mac ?? '—', isDark),
        _row(
          'MTU',
          stats != null && stats.mtu > 0 ? '${stats.mtu}' : '—',
          isDark,
        ),
        _row(
          'Link speed',
          stats != null && stats.baudrate > 0
              ? '${(stats.baudrate / 1e6).toStringAsFixed(0)} Mb/s'
              : '—',
          isDark,
        ),
        if (iface != null && iface.ipv6.isNotEmpty)
          _row('IPv6', iface.ipv6.join('\n'), isDark, multiline: true),
        _row(
          'Gateway',
          [
            info.defaultGateway ?? '—',
            if (_service.gatewayMac != null)
              '(${_service.gatewayMac}${_service.gatewayVendor != null ? ' · ${_service.gatewayVendor}' : ''})',
          ].join(' '),
          isDark,
        ),
        if (info.ipv6Gateway != null)
          _row('Gateway (IPv6)', info.ipv6Gateway!, isDark),
        if (dhcp.serverIdentifier != null ||
            dhcp.leaseEnd != null ||
            dhcp.router != null) ...[
          _row('DHCP server', dhcp.serverIdentifier ?? '—', isDark),
          if (dhcp.leaseEnd != null)
            _row('Lease expires', _fmtDateTime(dhcp.leaseEnd!), isDark),
          if (dhcp.leaseStart != null)
            _row('Lease started', _fmtDateTime(dhcp.leaseStart!), isDark),
          if (dhcp.domainName != null)
            _row('DHCP domain', dhcp.domainName!, isDark),
        ],
      ],
    );
  }

  Widget _dnsCard(ConnectionInfo info, bool isDark) {
    return _section(
      icon: Icons.dns_outlined,
      title: 'DNS & Proxy',
      isDark: isDark,
      rows: [
        _row(
          'DNS servers',
          info.dnsServers.isEmpty ? '—' : info.dnsServers.join('\n'),
          isDark,
          multiline: info.dnsServers.length > 1,
        ),
        if (info.searchDomains.isNotEmpty)
          _row('Search domains', info.searchDomains.join(', '), isDark),
        _row('Proxy', info.proxies.summary ?? 'Off', isDark),
        if (info.proxies.exceptions.isNotEmpty)
          _row(
            'Bypass list',
            info.proxies.exceptions.take(5).join(', ') +
                (info.proxies.exceptions.length > 5 ? '…' : ''),
            isDark,
          ),
      ],
    );
  }

  Widget _trafficCard(ConnectionInfo info, bool isDark) {
    final s = info.primaryStats;
    return _section(
      icon: Icons.speed_outlined,
      title: 'Traffic (since boot)',
      isDark: isDark,
      rows: [
        _row(
          'Received',
          s != null
              ? '${_fmtBytes(s.rxBytes)} (${_fmtCount(s.rxPackets)} packets)'
              : '—',
          isDark,
        ),
        _row(
          'Sent',
          s != null
              ? '${_fmtBytes(s.txBytes)} (${_fmtCount(s.txPackets)} packets)'
              : '—',
          isDark,
        ),
        if (_service.rxBytesPerSec != null || _service.txBytesPerSec != null)
          _row(
            'Current rate',
            '↓ ${_fmtRate(_service.rxBytesPerSec)}  ↑ ${_fmtRate(_service.txBytesPerSec)}',
            isDark,
          ),
        _row(
          'Errors',
          s != null
              ? 'in ${s.rxErrors} · out ${s.txErrors} · drops ${s.rxQDrops}'
              : '—',
          isDark,
        ),
        _row(
          'Uptime',
          info.uptime != null ? _fmtUptime(info.uptime!) : '—',
          isDark,
        ),
        if (info.bootTime != null)
          _row('Boot time', _fmtDateTime(info.bootTime!), isDark),
      ],
    );
  }

  Widget _interfacesCard(ConnectionInfo info, bool isDark) {
    final others =
        _service.network?.interfaces
            .where((i) => i.isUp && !i.isLoopback)
            .toList() ??
        [];
    if (others.isEmpty) return const SizedBox.shrink();

    return _section(
      icon: Icons.device_hub_outlined,
      title: 'Interfaces',
      isDark: isDark,
      rows: [
        for (final i in others)
          _row(
            i.name + (i.name == info.primaryInterface ? ' (primary)' : ''),
            [
              i.ip,
              if (i.cidr != null) '(${i.cidr})',
              if (_service.info?.interfaces[i.name] != null)
                '↓ ${_fmtBytes(_service.info!.interfaces[i.name]!.rxBytes)}',
            ].join(' '),
            isDark,
          ),
      ],
    );
  }

  Widget _systemCard(ConnectionInfo info, bool isDark) {
    return _section(
      icon: Icons.public_outlined,
      title: 'System',
      isDark: isDark,
      rows: [
        _row('Hostname', info.hostname ?? '—', isDark),
        _row(
          'Public IP',
          _service.publicIp ??
              (_service.publicIpChecked ? 'Unavailable' : 'Checking…'),
          isDark,
        ),
      ],
    );
  }

  // --- Building blocks ----------------------------------------------------

  Widget _section({
    required IconData icon,
    required String title,
    required bool isDark,
    required List<Widget> rows,
  }) {
    final themeColor = theme_manager.ThemeManager().themeColor;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        color: isDark ? Colors.grey.shade800 : Colors.white,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: isDark ? Colors.grey.shade700 : Colors.grey.shade200,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.2 : 0.04),
            offset: const Offset(0, 2),
            blurRadius: 8,
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(6),
                decoration: BoxDecoration(
                  color: isDark
                      ? Colors.blue.shade900.withValues(alpha: 0.3)
                      : Colors.blue.shade50,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(icon, size: 18, color: themeColor),
              ),
              const SizedBox(width: 10),
              TDText(
                title,
                font: TDTheme.of(context).fontTitleMedium,
                textColor: isDark ? Colors.white : Colors.black,
                fontWeight: FontWeight.w600,
              ),
            ],
          ),
          const SizedBox(height: 10),
          ...rows,
        ],
      ),
    );
  }

  /// Informational fields copy their value on long-press (or a
  /// right-click on desktop) — same affordance as the device detail view.
  void _copyField(String label, String value) {
    if (value.isEmpty || value == '—') return;
    Clipboard.setData(ClipboardData(text: value));
    TDToast.showText('$label copied', context: context);
  }

  Widget _row(
    String label,
    String value,
    bool isDark, {
    bool multiline = false,
  }) {
    final valueColor = isDark ? Colors.white : Colors.black87;
    final labelColor = isDark ? Colors.grey.shade400 : Colors.grey.shade600;
    return GestureDetector(
      behavior: HitTestBehavior.opaque,
      onLongPress: () => _copyField(label, value),
      onSecondaryTapUp: (_) => _copyField(label, value),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Row(
          crossAxisAlignment: multiline
              ? CrossAxisAlignment.start
              : CrossAxisAlignment.center,
          children: [
            SizedBox(
              width: 120,
              child: TDText(
                label,
                font: TDTheme.of(context).fontBodyMedium,
                textColor: labelColor,
              ),
            ),
            Expanded(
              child: TDText(
                value,
                font: TDTheme.of(context).fontBodyMedium,
                textColor: valueColor,
                fontWeight: FontWeight.w600,
                textAlign: TextAlign.right,
              ),
            ),
          ],
        ),
      ),
    );
  }

  InterfaceInfo? _primaryInterfaceInfo() {
    final net = _service.network;
    final primary = _service.info?.primaryInterface;
    if (net == null) return null;
    if (primary != null) {
      for (final i in net.interfaces) {
        if (i.name == primary) return i;
      }
    }
    return net.primary;
  }

  // --- Formatting ---------------------------------------------------------

  String _fmtBytes(int bytes) {
    if (bytes >= 1 << 30) {
      return '${(bytes / (1 << 30)).toStringAsFixed(2)} GB';
    }
    if (bytes >= 1 << 20) {
      return '${(bytes / (1 << 20)).toStringAsFixed(1)} MB';
    }
    if (bytes >= 1 << 10) return '${(bytes / (1 << 10)).toStringAsFixed(1)} KB';
    return '$bytes B';
  }

  String _fmtRate(double? bytesPerSec) {
    if (bytesPerSec == null) return '—';
    if (bytesPerSec < 0) bytesPerSec = 0;
    if (bytesPerSec >= 1 << 20) {
      return '${(bytesPerSec / (1 << 20)).toStringAsFixed(1)} MB/s';
    }
    if (bytesPerSec >= 1 << 10) {
      return '${(bytesPerSec / (1 << 10)).toStringAsFixed(1)} KB/s';
    }
    return '${bytesPerSec.toStringAsFixed(0)} B/s';
  }

  String _fmtCount(int n) {
    if (n >= 1000000) return '${(n / 1000000).toStringAsFixed(1)}M';
    if (n >= 1000) return '${(n / 1000).toStringAsFixed(1)}K';
    return '$n';
  }

  String _fmtUptime(Duration d) {
    final days = d.inDays;
    final hours = d.inHours % 24;
    final mins = d.inMinutes % 60;
    if (days > 0) return '${days}d ${hours}h ${mins}m';
    if (hours > 0) return '${hours}h ${mins}m';
    return '${mins}m';
  }

  String _fmtDateTime(DateTime t) {
    final d = t.toLocal();
    String two(int v) => v.toString().padLeft(2, '0');
    return '${d.year}-${two(d.month)}-${two(d.day)} '
        '${two(d.hour)}:${two(d.minute)}';
  }
}
