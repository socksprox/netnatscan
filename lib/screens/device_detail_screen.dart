import 'package:flutter/material.dart';

import '../models/network_device.dart';
import '../services/mdns_discovery.dart';
import '../services/network_scanner.dart';
import '../services/theme_manager.dart' as theme_manager;
import '../widgets/centered_button.dart';
import '../widgets/custom_app_bar.dart';
import '../widgets/squircle_input.dart';
import '../widgets/tdesign.dart';
import '../widgets/theme_tab_selector.dart';

/// Everything a scan learned about one device: identity, network facts,
/// and each Bonjour service with its SRV target, port and TXT answers.
class DeviceDetailScreen extends StatefulWidget {
  final NetworkDevice device;
  final NetworkScanner scanner;

  /// Set from the device list context menu — starts a common port scan
  /// as soon as the page opens.
  final bool autoPortScan;

  const DeviceDetailScreen({
    super.key,
    required this.device,
    required this.scanner,
    this.autoPortScan = false,
  });

  @override
  State<DeviceDetailScreen> createState() => _DeviceDetailScreenState();
}

class _DeviceDetailScreenState extends State<DeviceDetailScreen> {
  bool _probing = false;
  bool? _probeAnswered;
  bool _scanningPorts = false;
  bool _portScanDone = false;
  int _presetIndex = 0;
  final _customPorts = TextEditingController();

  NetworkDevice get d => widget.device;

  @override
  void initState() {
    super.initState();
    if (widget.autoPortScan) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _scanPorts());
    }
  }

  @override
  void dispose() {
    _customPorts.dispose();
    super.dispose();
  }

  Future<void> _probe() async {
    setState(() {
      _probing = true;
      _probeAnswered = null;
    });
    final answered = await widget.scanner.probeDevice(d);
    if (mounted) {
      setState(() {
        _probing = false;
        _probeAnswered = answered;
      });
    }
  }

  /// Custom spec wins over the preset: `22,80,443` or ranges `8000-8100`.
  List<int> _selectedPorts() {
    final spec = _customPorts.text.trim();
    if (spec.isNotEmpty) {
      final ports = <int>{};
      for (final part in spec.split(',')) {
        final range = part.trim().split('-');
        final a = int.tryParse(range.first);
        final b = int.tryParse(range.last);
        if (a == null || b == null) continue;
        for (var p = a; p <= b && p <= a + 4096; p++) {
          ports.add(p);
        }
      }
      return ports.toList();
    }
    return _presetIndex == 0
        ? NetworkScanner.commonScanPorts
        : NetworkScanner.extendedScanPorts;
  }

  Future<void> _scanPorts() async {
    final ports = _selectedPorts();
    if (ports.isEmpty) {
      TDToast.showText('No valid ports — try e.g. 22,80,443', context: context);
      return;
    }
    setState(() {
      _scanningPorts = true;
      _portScanDone = false;
    });
    await widget.scanner.scanPorts(d, ports);
    if (mounted) {
      setState(() {
        _scanningPorts = false;
        _portScanDone = true;
      });
    }
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
            _card(isDark, () {
              final rows = <({String label, String value})>[
                (label: 'IP address', value: d.ip),
                if (d.mac != null) (label: 'MAC address', value: d.mac!),
                if (d.vendor != null) (label: 'Vendor', value: d.vendor!),
                (label: 'Type', value: d.typeLabel),
                if (d.rttMs != null) (label: 'Latency', value: '${d.rttMs} ms'),
                if (d.openPorts.isNotEmpty)
                  (
                    label: 'Open ports',
                    value: (d.openPorts.toList()..sort()).join(', '),
                  ),
                if (d.tlsSubject != null)
                  (
                    label: 'TLS cert',
                    value: d.tlsSubject!
                        .replaceAll(RegExp(r'^/'), '')
                        .replaceAll('/', ' · '),
                  ),
                if (d.lastSeenAt != null)
                  (
                    label: 'Last live answer',
                    value: _formatTime(d.lastSeenAt!),
                  ),
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
            _sectionTitle('Names', isDark),
            const SizedBox(height: 8),
            _card(isDark, () {
              final rows = <({String label, String value})>[
                (label: 'Name', value: d.mdnsName ?? '—'),
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
            if (d.upnp != null) ...[
              const SizedBox(height: 16),
              _sectionTitle('UPnP / SSDP', isDark),
              const SizedBox(height: 8),
              _card(isDark, () {
                final u = d.upnp!;
                final rows = <({String label, String value})>[
                  if (u.friendlyName != null)
                    (label: 'Friendly name', value: u.friendlyName!),
                  if (u.manufacturer != null)
                    (label: 'Manufacturer', value: u.manufacturer!),
                  if (u.modelName != null)
                    (
                      label: 'Model',
                      value: u.modelNumber != null
                          ? '${u.modelName} ${u.modelNumber}'
                          : u.modelName!,
                    ),
                  if (u.deviceType != null)
                    (label: 'Device type', value: u.deviceType!),
                  if (u.server != null) (label: 'Server', value: u.server!),
                  if (u.sts.isNotEmpty)
                    (label: 'Services', value: u.sts.join(', ')),
                  if (u.location != null)
                    (label: 'Description', value: u.location!),
                  if (u.serialNumber != null)
                    (label: 'Serial', value: u.serialNumber!),
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
            ],
            if (d.netbiosNames.isNotEmpty) ...[
              const SizedBox(height: 16),
              _sectionTitle('NetBIOS', isDark),
              const SizedBox(height: 8),
              _card(isDark, () {
                final rows = d.netbiosNames;
                return [
                  for (var i = 0; i < rows.length; i++)
                    _row(
                      rows[i].unique ? 'Name' : 'Group',
                      rows[i].label,
                      isDark,
                      last: i == rows.length - 1,
                    ),
                ];
              }()),
            ],
            if (d.httpServer != null || d.httpTitle != null) ...[
              const SizedBox(height: 16),
              _sectionTitle('Web interface', isDark),
              const SizedBox(height: 8),
              _card(isDark, () {
                final rows = <({String label, String value})>[
                  if (d.httpTitle != null)
                    (label: 'Title', value: d.httpTitle!),
                  if (d.httpServer != null)
                    (label: 'Server', value: d.httpServer!),
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
            ],
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
            if (d.isStandby || d.mdnsServices.isEmpty)
              _card(isDark, [
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 4),
                  child: TDText(
                    d.isStandby
                        ? 'Device is silent — data below is the last live '
                              'answer${d.lastSeenAt != null ? ' (${_formatTime(d.lastSeenAt!)})' : ''}.'
                              '${d.mdnsServices.isEmpty ? ' Types seen earlier: ${d.mdnsTypes.isEmpty ? '—' : d.mdnsTypes.join(', ')}' : ''}'
                        : 'No services answered.',
                    font: TDTheme.of(context).fontBodySmall,
                    textColor: isDark
                        ? Colors.grey.shade400
                        : Colors.grey.shade600,
                  ),
                ),
              ]),
            if (d.mdnsServices.isNotEmpty)
              for (final s in d.mdnsServices) ...[
                _serviceCard(s, isDark, themeColor),
                const SizedBox(height: 8),
              ],
            const SizedBox(height: 8),
            CenteredButton(
              text: _probing ? 'Querying…' : 'Query via Bonjour (mDNS)',
              icon: _probing ? null : Icons.wifi_tethering,
              isPrimary: true,
              isBlock: true,
              disabled: _probing,
              onTap: _probe,
            ),
            const SizedBox(height: 8),
            TDText(
              'Sends one unicast Bonjour query at this device — catches it '
              'if it just woke. It cannot wake a sleeping device.',
              font: TDTheme.of(context).fontBodySmall,
              textColor: isDark ? Colors.grey.shade500 : Colors.grey.shade500,
            ),
            if (_probeAnswered != null) ...[
              const SizedBox(height: 8),
              _card(isDark, [
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 4),
                  child: TDText(
                    _probeAnswered!
                        ? 'Answered — identity and services above are '
                              'fresh from this device.'
                        : 'No answer — device is still silent. Data shown '
                              'is from the last live answer'
                              '${d.lastSeenAt != null ? ' (${_formatTime(d.lastSeenAt!)})' : ''}.',
                    font: TDTheme.of(context).fontBodySmall,
                    textColor: _probeAnswered!
                        ? themeColor
                        : (isDark
                              ? Colors.grey.shade400
                              : Colors.grey.shade600),
                  ),
                ),
              ]),
            ],
            const SizedBox(height: 16),
            _sectionTitle('Port scan', isDark),
            const SizedBox(height: 8),
            TDesignTabSelector(
              height: 36,
              tabs: const [
                TDesignTabItem(text: 'Common'),
                TDesignTabItem(text: 'Extended'),
              ],
              initialIndex: _presetIndex,
              onTabChanged: (i) => setState(() => _presetIndex = i),
            ),
            const SizedBox(height: 8),
            SquircleInput(
              controller: _customPorts,
              hintText: 'Custom ports, e.g. 22,80,443,8000-8100',
              enabled: !_scanningPorts,
              onSubmitted: (_) => _scanPorts(),
            ),
            const SizedBox(height: 8),
            CenteredButton(
              text: _scanningPorts
                  ? 'Scanning…'
                  : 'Scan ${_customPorts.text.trim().isNotEmpty ? _selectedPorts().length : (_presetIndex == 0 ? NetworkScanner.commonScanPorts.length : NetworkScanner.extendedScanPorts.length)} ports',
              icon: _scanningPorts ? null : Icons.lan_outlined,
              isBlock: true,
              disabled: _scanningPorts,
              onTap: _scanPorts,
            ),
            if (_portScanDone || d.openPorts.isNotEmpty) ...[
              const SizedBox(height: 8),
              _card(isDark, [
                if (d.openPorts.isEmpty)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: TDText(
                      'No open ports found',
                      font: TDTheme.of(context).fontBodySmall,
                      textColor: isDark
                          ? Colors.grey.shade400
                          : Colors.grey.shade600,
                    ),
                  )
                else
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: Wrap(
                      spacing: 6,
                      runSpacing: 6,
                      children: [
                        for (final p in d.openPorts.toList()..sort())
                          _portChip(p, isDark, themeColor),
                      ],
                    ),
                  ),
              ]),
            ],
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

  Widget _portChip(int port, bool isDark, Color themeColor) {
    final service = NetworkScanner.portServices[port];
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: themeColor.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: themeColor.withValues(alpha: 0.3)),
      ),
      child: TDText(
        service != null ? '$port · $service' : '$port',
        font: TDTheme.of(context).fontBodySmall,
        textColor: isDark ? Colors.white : Colors.black87,
        fontWeight: FontWeight.w600,
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
