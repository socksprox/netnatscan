import 'package:flutter/material.dart';

import '../models/network_device.dart';
import '../services/mdns_discovery.dart';
import '../services/network_scanner.dart';
import '../services/theme_manager.dart' as theme_manager;
import '../widgets/centered_button.dart';
import '../widgets/custom_app_bar.dart';
import '../widgets/tdesign.dart';

/// Everything a scan learned about one device: identity, network facts,
/// and each Bonjour service with its SRV target, port and TXT answers.
class DeviceDetailScreen extends StatefulWidget {
  final NetworkDevice device;
  final NetworkScanner scanner;

  const DeviceDetailScreen({
    super.key,
    required this.device,
    required this.scanner,
  });

  @override
  State<DeviceDetailScreen> createState() => _DeviceDetailScreenState();
}

class _DeviceDetailScreenState extends State<DeviceDetailScreen> {
  bool _probing = false;

  NetworkDevice get d => widget.device;

  Future<void> _probe() async {
    setState(() => _probing = true);
    await widget.scanner.probeDevice(d);
    if (mounted) setState(() => _probing = false);
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final themeColor = theme_manager.ThemeManager().themeColor;
    return Scaffold(
      backgroundColor: isDark ? Colors.grey.shade900 : Colors.grey.shade50,
      appBar: CustomAppBar(title: d.displayName),
      body: AnimatedBuilder(
        animation: widget.scanner,
        builder: (context, _) => ListView(
          padding: const EdgeInsets.all(16),
          children: [
            _header(isDark, themeColor),
            const SizedBox(height: 16),
            _sectionTitle('Device', isDark),
            const SizedBox(height: 8),
            _card(isDark, [
              _row('IP address', d.ip, isDark),
              if (d.mac != null) _row('MAC address', d.mac!, isDark),
              if (d.vendor != null) _row('Vendor', d.vendor!, isDark),
              _row('Type', d.typeLabel, isDark),
              if (d.rttMs != null) _row('Latency', '${d.rttMs} ms', isDark),
              if (d.lastSeenAt != null)
                _row(
                  d.isStandby ? 'Last seen (cached)' : 'Last seen',
                  _formatTime(d.lastSeenAt!),
                  isDark,
                  last: true,
                ),
            ]),
            const SizedBox(height: 16),
            _sectionTitle('Names', isDark),
            const SizedBox(height: 8),
            _card(isDark, () {
              final rows = <({String label, String value})>[
                (label: 'mDNS name', value: d.mdnsName ?? '—'),
                if (d.hostname != null && d.hostname != d.mdnsName)
                  (label: 'Hostname (PTR)', value: d.hostname!),
                if (d.nameSourceText.isNotEmpty)
                  (label: 'Name via', value: d.nameSourceText),
                if (d.seenNames.isNotEmpty)
                  (label: 'Other names', value: d.seenNames.join(', ')),
              ];
              return [
                for (var i = 0; i < rows.length; i++)
                  _row(
                    rows[i].label,
                    rows[i].value,
                    isDark,
                    last: i == rows.length - 1,
                  ),
              ];
            }()),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(child: _sectionTitle('Bonjour services', isDark)),
                TDText(
                  '${d.mdnsServices.length}',
                  font: TDTheme.of(context).fontBodySmall,
                  textColor: isDark
                      ? Colors.grey.shade400
                      : Colors.grey.shade600,
                ),
              ],
            ),
            const SizedBox(height: 8),
            if (d.mdnsServices.isEmpty)
              _card(isDark, [
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 4),
                  child: TDText(
                    d.isStandby
                        ? 'Sleeping — identity restored from cache. '
                              'Types seen earlier: '
                              '${d.mdnsTypes.isEmpty ? '—' : d.mdnsTypes.join(', ')}'
                        : 'No services answered.',
                    font: TDTheme.of(context).fontBodySmall,
                    textColor: isDark
                        ? Colors.grey.shade400
                        : Colors.grey.shade600,
                  ),
                ),
              ])
            else
              for (final s in d.mdnsServices) ...[
                _serviceCard(s, isDark, themeColor),
                const SizedBox(height: 8),
              ],
            const SizedBox(height: 20),
            CenteredButton(
              text: _probing ? 'Probing…' : 'Probe again',
              icon: _probing ? null : Icons.refresh,
              isPrimary: true,
              disabled: _probing,
              onTap: _probe,
            ),
            const SizedBox(height: 8),
            TDText(
              'Sends a unicast mDNS query straight at this device.',
              font: TDTheme.of(context).fontBodySmall,
              textColor: isDark ? Colors.grey.shade500 : Colors.grey.shade500,
            ),
          ],
        ),
      ),
    );
  }

  Widget _header(bool isDark, Color themeColor) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: _cardDecoration(isDark),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: isDark
                  ? Colors.blue.shade900.withValues(alpha: 0.3)
                  : Colors.blue.shade50,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(d.icon, size: 24, color: themeColor),
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
                        d.displayName,
                        font: TDTheme.of(context).fontTitleMedium,
                        textColor: isDark ? Colors.white : Colors.black,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    if (d.isStandby) ...[
                      const SizedBox(width: 6),
                      _chip(
                        'Standby',
                        isDark ? Colors.grey.shade400 : Colors.grey.shade600,
                        Icons.bedtime,
                      ),
                    ],
                  ],
                ),
                const SizedBox(height: 2),
                TDText(
                  d.typeLabel,
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

  Widget _serviceCard(MdnsService s, bool isDark, Color themeColor) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: _cardDecoration(isDark),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.wifi_tethering, size: 16, color: themeColor),
              const SizedBox(width: 8),
              Expanded(
                child: TDText(
                  s.name,
                  font: TDTheme.of(context).fontBodyMedium,
                  textColor: isDark ? Colors.white : Colors.black,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          _kv(
            'Service',
            '${s.type}${s.port != null ? ' · port ${s.port}' : ''}',
            isDark,
          ),
          if (s.host != null) _kv('Host', s.host!, isDark),
          if (s.ips.isNotEmpty) _kv('Addresses', s.ips.join(', '), isDark),
          for (final e in s.txt.entries) _kv(e.key, e.value, isDark),
        ],
      ),
    );
  }

  Widget _kv(String k, String v, bool isDark) => Padding(
    padding: const EdgeInsets.only(top: 4),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 90,
          child: TDText(
            k,
            font: TDTheme.of(context).fontBodySmall,
            textColor: isDark ? Colors.grey.shade500 : Colors.grey.shade500,
          ),
        ),
        Expanded(
          child: TDText(
            v,
            font: TDTheme.of(context).fontBodySmall,
            textColor: isDark ? Colors.grey.shade300 : Colors.grey.shade700,
          ),
        ),
      ],
    ),
  );

  Widget _sectionTitle(String text, bool isDark) => TDText(
    text,
    font: TDTheme.of(context).fontTitleMedium,
    textColor: isDark ? Colors.white : Colors.black,
    fontWeight: FontWeight.w600,
  );

  Widget _card(bool isDark, List<Widget> children) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
    decoration: _cardDecoration(isDark),
    child: Column(children: children),
  );

  Widget _row(String label, String value, bool isDark, {bool last = false}) =>
      Padding(
        padding: const EdgeInsets.symmetric(vertical: 6),
        child: Column(
          children: [
            Row(
              children: [
                TDText(
                  label,
                  font: TDTheme.of(context).fontBodySmall,
                  textColor: isDark
                      ? Colors.grey.shade400
                      : Colors.grey.shade600,
                ),
                const Spacer(),
                Flexible(
                  child: TDText(
                    value,
                    font: TDTheme.of(context).fontBodyMedium,
                    textColor: isDark ? Colors.white : Colors.black87,
                    fontWeight: FontWeight.w600,
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
      );

  Widget _chip(String text, Color color, IconData icon) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
    decoration: BoxDecoration(
      color: color.withValues(alpha: 0.12),
      borderRadius: BorderRadius.circular(4),
    ),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 11, color: color),
        const SizedBox(width: 3),
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

  String _formatTime(DateTime t) =>
      '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';
}
