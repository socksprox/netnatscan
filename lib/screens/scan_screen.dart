import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../widgets/tdesign.dart';

import '../models/network_device.dart';
import '../services/network_scanner.dart';
import '../services/theme_manager.dart' as theme_manager;
import '../widgets/centered_button.dart';
import '../widgets/custom_app_bar.dart';
import 'device_detail_screen.dart';

class ScanScreen extends StatefulWidget {
  const ScanScreen({super.key});

  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  final NetworkScanner _scanner = NetworkScanner();

  @override
  void initState() {
    super.initState();
    _scanner.refreshNetworkInfo().then((_) => _scanner.scan());
  }

  void _cycleTheme() {
    final tm = theme_manager.ThemeManager();
    final next = switch (tm.themeMode) {
      theme_manager.ThemeMode.system => theme_manager.ThemeMode.light,
      theme_manager.ThemeMode.light => theme_manager.ThemeMode.dark,
      theme_manager.ThemeMode.dark => theme_manager.ThemeMode.system,
    };
    tm.setThemeMode(next);
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Scaffold(
      backgroundColor: isDark ? Colors.grey.shade900 : Colors.grey.shade50,
      appBar: CustomAppBar(
        title: 'Network Scan',
        automaticallyImplyLeading: false,
        actions: [
          Material(
            color: Colors.transparent,
            child: InkWell(
              onTap: _cycleTheme,
              borderRadius: BorderRadius.circular(8),
              child: Padding(
                padding: const EdgeInsets.all(8),
                child: Icon(
                  switch (theme_manager.ThemeManager().themeMode) {
                    theme_manager.ThemeMode.system =>
                      Icons.brightness_auto_outlined,
                    theme_manager.ThemeMode.light => Icons.light_mode_outlined,
                    theme_manager.ThemeMode.dark => Icons.dark_mode_outlined,
                  },
                  color: isDark ? Colors.white : Colors.black,
                  size: 20,
                ),
              ),
            ),
          ),
          const SizedBox(width: 4),
        ],
      ),
      body: AnimatedBuilder(
        animation: _scanner,
        builder: (context, _) => _buildBody(context, isDark),
      ),
    );
  }

  Widget _buildBody(BuildContext context, bool isDark) {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          _NetworkCard(scanner: _scanner, isDark: isDark),
          const SizedBox(height: 16),
          if (_scanner.scanning) ...[
            LinearProgressIndicator(
              value: _scanner.progress.fraction == 0
                  ? null
                  : _scanner.progress.fraction,
              borderRadius: BorderRadius.circular(4),
              color: theme_manager.ThemeManager().themeColor,
              backgroundColor: isDark
                  ? Colors.grey.shade800
                  : Colors.grey.shade200,
            ),
            const SizedBox(height: 8),
            TDText(
              _scanner.progress.label,
              font: TDTheme.of(context).fontBodySmall,
              textColor: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
            ),
            const SizedBox(height: 12),
          ],
          if (_scanner.scanNote != null) ...[
            TDText(
              _scanner.scanNote!,
              font: TDTheme.of(context).fontBodySmall,
              textColor: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
            ),
            const SizedBox(height: 8),
          ],
          if (_scanner.devices.isNotEmpty) ...[
            Row(
              children: [
                TDText(
                  '${_scanner.devices.length} device${_scanner.devices.length == 1 ? '' : 's'}',
                  font: TDTheme.of(context).fontTitleMedium,
                  textColor: isDark ? Colors.white : Colors.black,
                  fontWeight: FontWeight.w600,
                ),
                const Spacer(),
                if (_scanner.lastScanAt != null && !_scanner.scanning)
                  TDText(
                    'Updated ${_formatTime(_scanner.lastScanAt!)}',
                    font: TDTheme.of(context).fontBodySmall,
                    textColor: isDark
                        ? Colors.grey.shade400
                        : Colors.grey.shade600,
                  ),
              ],
            ),
            const SizedBox(height: 12),
          ],
          Expanded(child: _buildList(context, isDark)),
        ],
      ),
    );
  }

  Widget _buildList(BuildContext context, bool isDark) {
    if (_scanner.devices.isEmpty) {
      if (_scanner.scanning) return const SizedBox.shrink();
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.lan_outlined,
              size: 32,
              color: isDark ? Colors.grey.shade700 : Colors.grey.shade300,
            ),
            const SizedBox(height: 12),
            TDText(
              _scanner.error ?? 'No devices found yet',
              font: TDTheme.of(context).fontTitleMedium,
              textColor: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
              fontWeight: FontWeight.w600,
            ),
            const SizedBox(height: 4),
            TDText(
              'Tap Scan to search your local network',
              font: TDTheme.of(context).fontBodySmall,
              textColor: isDark ? Colors.grey.shade500 : Colors.grey.shade500,
            ),
          ],
        ),
      );
    }
    return ListView.separated(
      itemCount: _scanner.devices.length,
      separatorBuilder: (_, _) => const SizedBox(height: 8),
      itemBuilder: (context, i) => _DeviceCard(
        device: _scanner.devices[i],
        isDark: isDark,
        scanner: _scanner,
      ),
    );
  }

  String _formatTime(DateTime t) =>
      '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';
}

class _NetworkCard extends StatelessWidget {
  final NetworkScanner scanner;
  final bool isDark;

  const _NetworkCard({required this.scanner, required this.isDark});

  @override
  Widget build(BuildContext context) {
    final themeColor = theme_manager.ThemeManager().themeColor;
    final iface = scanner.network?.primary;
    final net = scanner.network;

    return Container(
      padding: const EdgeInsets.all(16),
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
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: isDark
                      ? Colors.blue.shade900.withValues(alpha: 0.3)
                      : Colors.blue.shade50,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(Icons.wifi, size: 20, color: themeColor),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    TDText(
                      iface != null
                          ? 'Network ${iface.cidr ?? iface.ip}'
                          : 'No network',
                      font: TDTheme.of(context).fontTitleMedium,
                      textColor: isDark ? Colors.white : Colors.black,
                      fontWeight: FontWeight.w600,
                    ),
                    TDText(
                      iface != null
                          ? 'Interface ${iface.name}'
                          : (scanner.error ?? 'Not connected'),
                      font: TDTheme.of(context).fontBodySmall,
                      textColor: isDark
                          ? Colors.grey.shade400
                          : Colors.grey.shade600,
                    ),
                  ],
                ),
              ),
              CenteredButton(
                text: scanner.scanning ? 'Scanning…' : 'Scan',
                icon: scanner.scanning ? null : Icons.radar,
                isPrimary: true,
                disabled: scanner.scanning || iface == null,
                onTap: () => scanner.scan(),
              ),
            ],
          ),
          if (iface != null) ...[
            const SizedBox(height: 14),
            Divider(
              height: 1,
              color: isDark ? Colors.grey.shade700 : Colors.grey.shade200,
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 24,
              runSpacing: 8,
              children: [
                _InfoItem(label: 'Your IP', value: iface.ip, isDark: isDark),
                _InfoItem(
                  label: 'Gateway',
                  value: net?.defaultGateway ?? '—',
                  isDark: isDark,
                ),
                _InfoItem(
                  label: 'Subnet',
                  value: iface.netmask ?? '—',
                  isDark: isDark,
                ),
                if (iface.mac != null)
                  _InfoItem(
                    label: 'Your MAC',
                    value: iface.mac!,
                    isDark: isDark,
                  ),
              ],
            ),
          ],
        ],
      ),
    );
  }
}

class _InfoItem extends StatelessWidget {
  final String label;
  final String value;
  final bool isDark;

  const _InfoItem({
    required this.label,
    required this.value,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        TDText(
          label,
          font: TDTheme.of(context).fontBodySmall,
          textColor: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
        ),
        const SizedBox(height: 2),
        TDText(
          value,
          font: TDTheme.of(context).fontBodyMedium,
          textColor: isDark ? Colors.white : Colors.black87,
          fontWeight: FontWeight.w600,
        ),
      ],
    );
  }
}

class _DeviceCard extends StatelessWidget {
  final NetworkDevice device;
  final bool isDark;
  final NetworkScanner scanner;

  const _DeviceCard({
    required this.device,
    required this.isDark,
    required this.scanner,
  });

  void _openDetail(BuildContext context, {bool autoPortScan = false}) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => DeviceDetailScreen(
          device: device,
          scanner: scanner,
          autoPortScan: autoPortScan,
        ),
      ),
    );
  }

  /// Right-click / long-press menu — heavier per-device probes live here
  /// so a normal scan stays cheap.
  Future<void> _showMenu(BuildContext context, Offset position) async {
    final choice = await showMenu<String>(
      context: context,
      position: RelativeRect.fromLTRB(
        position.dx,
        position.dy,
        position.dx,
        position.dy,
      ),
      items: [
        const PopupMenuItem(value: 'portscan', child: Text('Port scan')),
        const PopupMenuItem(value: 'copyip', child: Text('Copy IP address')),
        if (device.mac != null)
          const PopupMenuItem(
            value: 'copymac',
            child: Text('Copy MAC address'),
          ),
      ],
    );
    if (!context.mounted) return;
    switch (choice) {
      case 'portscan':
        _openDetail(context, autoPortScan: true);
      case 'copyip':
        Clipboard.setData(ClipboardData(text: device.ip));
        TDToast.showText('IP copied', context: context);
      case 'copymac':
        Clipboard.setData(ClipboardData(text: device.mac!));
        TDToast.showText('MAC copied', context: context);
    }
  }

  @override
  Widget build(BuildContext context) {
    final themeColor = theme_manager.ThemeManager().themeColor;
    final isSelf = device.isSelf;

    return GestureDetector(
      onSecondaryTapUp: (d) => _showMenu(context, d.globalPosition),
      child: Material(
        borderRadius: BorderRadius.circular(10),
        clipBehavior: Clip.antiAlias,
        color: Colors.transparent,
        child: Ink(
          decoration: BoxDecoration(
            color: isDark ? Colors.grey.shade800 : Colors.white,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(
              color: isSelf
                  ? themeColor.withValues(alpha: 0.5)
                  : (isDark ? Colors.grey.shade700 : Colors.grey.shade200),
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: isDark ? 0.2 : 0.03),
                offset: const Offset(0, 1),
                blurRadius: 3,
              ),
            ],
          ),
          child: InkWell(
            onTap: () => _openDetail(context),
            onLongPress: () {
              final box = context.findRenderObject() as RenderBox?;
              final pos =
                  box?.localToGlobal(box.size.center(Offset.zero)) ??
                  Offset.zero;
              _showMenu(context, pos);
            },
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: isDark
                          ? Colors.blue.shade900.withValues(alpha: 0.3)
                          : Colors.blue.shade50,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Icon(device.icon, size: 20, color: themeColor),
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
                                device.displayName,
                                font: TDTheme.of(context).fontBodyMedium,
                                textColor: isDark ? Colors.white : Colors.black,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            if (isSelf) ...[
                              const SizedBox(width: 6),
                              _Tag(text: 'This device', color: themeColor),
                            ] else if (device.isGateway) ...[
                              const SizedBox(width: 6),
                              _Tag(
                                text: 'Router',
                                color: isDark
                                    ? Colors.orange.shade300
                                    : Colors.orange.shade700,
                              ),
                            ],
                            if (device.isStandby) ...[
                              const SizedBox(width: 6),
                              _Tag(
                                text: 'Standby',
                                icon: Icons.bedtime,
                                color: isDark
                                    ? Colors.grey.shade400
                                    : Colors.grey.shade600,
                              ),
                            ],
                          ],
                        ),
                        const SizedBox(height: 2),
                        TDText(
                          device.ip +
                              (device.mac != null ? '  ·  ${device.mac}' : ''),
                          font: TDTheme.of(context).fontBodySmall,
                          textColor: isDark
                              ? Colors.grey.shade400
                              : Colors.grey.shade600,
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 12),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.end,
                    children: [
                      TDText(
                        device.vendor ?? device.typeLabel,
                        font: TDTheme.of(context).fontBodySmall,
                        textColor: isDark
                            ? Colors.grey.shade400
                            : Colors.grey.shade600,
                        fontWeight: FontWeight.w500,
                      ),
                      if (device.nameSourceText.isNotEmpty)
                        TDText(
                          device.nameSourceText,
                          font: TDTheme.of(context).fontBodySmall,
                          textColor: isDark
                              ? Colors.grey.shade500
                              : Colors.grey.shade500,
                        ),
                      if (device.rttMs != null)
                        TDText(
                          '${device.rttMs} ms',
                          font: TDTheme.of(context).fontBodySmall,
                          textColor: isDark
                              ? Colors.grey.shade500
                              : Colors.grey.shade500,
                        ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _Tag extends StatelessWidget {
  final String text;
  final Color color;
  final IconData? icon;

  const _Tag({required this.text, required this.color, this.icon});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            Icon(icon, size: 11, color: color),
            const SizedBox(width: 3),
          ],
          Text(
            text,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: color,
              height: 1.2,
            ),
          ),
        ],
      ),
    );
  }
}
