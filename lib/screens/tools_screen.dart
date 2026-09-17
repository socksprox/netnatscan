import 'package:flutter/material.dart';

import '../services/theme_manager.dart' as theme_manager;
import '../services/tool_service.dart';
import '../widgets/app_navigation.dart';
import '../widgets/centered_button.dart';
import '../widgets/squircle_input.dart';
import '../widgets/tdesign.dart';
import '../widgets/theme_tab_selector.dart';

/// Fourth tab: ping / traceroute tools in the style of NetAnalyzer's
/// Tools screen. Idle shows just two top buttons — history on the left,
/// New on the right. New opens a target + options form where the right
/// button becomes Start; a running job turns it into Stop.
enum _Mode { idle, history, config, active, viewing }

class ToolsScreen extends StatefulWidget {
  const ToolsScreen({super.key});

  @override
  State<ToolsScreen> createState() => _ToolsScreenState();
}

class _ToolsScreenState extends State<ToolsScreen> {
  final ToolService _service = ToolService();

  _Mode _mode = _Mode.idle;
  _Mode _returnMode = _Mode.idle; // where "back" from history lands
  ToolRun? _viewing;

  // -- form state ------------------------------------------------------------
  int _tool = 0; // 0 = ping, 1 = route
  int _proto = 0; // 0 = icmp, 1 = udp, 2 = tcp
  int _ipVersion = 0; // 0 = auto, 1 = ipv4, 2 = ipv6
  bool _dontFragment = false;
  bool _audible = false;
  bool _udpProbes = false;

  final _target = TextEditingController();
  final _countCtl = TextEditingController(text: '5');
  final _delayCtl = TextEditingController(text: '1000');
  final _payloadCtl = TextEditingController(text: '56');
  final _portCtl = TextEditingController(text: '80');
  final _maxHopsCtl = TextEditingController(text: '30');
  final _probesCtl = TextEditingController(text: '3');
  final _maxDelayCtl = TextEditingController(text: '2000');
  final _minDelayCtl = TextEditingController(text: '100');

  final _scroll = ScrollController();

  @override
  void initState() {
    super.initState();
    _target.addListener(() => setState(() {}));
    // Follow new replies/hops as they stream in.
    _service.addListener(_scrollToEnd);
  }

  @override
  void dispose() {
    _service.dispose();
    _scroll.dispose();
    for (final c in [
      _target,
      _countCtl,
      _delayCtl,
      _payloadCtl,
      _portCtl,
      _maxHopsCtl,
      _probesCtl,
      _maxDelayCtl,
      _minDelayCtl,
    ]) {
      c.dispose();
    }
    super.dispose();
  }

  void _scrollToEnd() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) {
        _scroll.jumpTo(_scroll.position.maxScrollExtent);
      }
    });
  }

  // -- actions -----------------------------------------------------------------

  void _goBack() {
    setState(() {
      if (_mode == _Mode.viewing) {
        _mode = _Mode.history;
        _viewing = null;
      } else if (_mode == _Mode.history) {
        _mode = _returnMode;
      } else {
        _mode = _Mode.idle;
      }
    });
  }

  void _showHistory() {
    setState(() {
      _returnMode = _mode == _Mode.history ? _Mode.idle : _mode;
      _mode = _Mode.history;
    });
  }

  void _start() {
    final target = _target.text.trim();
    if (target.isEmpty) return;
    final ipVersion = const ['auto', 'ipv4', 'ipv6'][_ipVersion];

    if (_tool == 0) {
      final proto = const ['icmp', 'udp', 'tcp'][_proto];
      final count = _intOf(_countCtl, 5, 1, 100);
      final interval = _intOf(_delayCtl, 1000, 50, 60000);
      final payload = _intOf(_payloadCtl, 56, 8, 65000);
      final port = _intOf(_portCtl, _proto == 1 ? 7 : 80, 1, 65535);
      final detail =
          '${proto.toUpperCase()} · $count× every $interval ms · $payload B'
          '${proto == 'icmp' ? '' : ' · port $port'}'
          '${_dontFragment ? ' · DF' : ''}';
      _service.startPing(target, {
        'protocol': proto,
        'count': count,
        'intervalMs': interval,
        'payloadBytes': payload,
        'dontFragment': _dontFragment,
        'audible': _audible,
        'port': port,
        'ipVersion': ipVersion,
        'detail': detail,
      });
    } else {
      final maxHops = _intOf(_maxHopsCtl, 30, 1, 64);
      final probes = _intOf(_probesCtl, 3, 1, 5);
      final maxDelay = _intOf(_maxDelayCtl, 2000, 200, 30000);
      final minDelay = _intOf(_minDelayCtl, 100, 0, 10000);
      final detail =
          '${_udpProbes ? 'UDP' : 'ICMP'} · $maxHops hops · $probes probes';
      _service.startRoute(target, {
        'udpProbes': _udpProbes,
        'maxHops': maxHops,
        'probesPerHop': probes,
        'maxDelayMs': maxDelay,
        'minDelayMs': minDelay,
        'ipVersion': ipVersion,
        'detail': detail,
      });
    }
    setState(() => _mode = _Mode.active);
  }

  int _intOf(TextEditingController c, int def, int min, int max) {
    final v = int.tryParse(c.text.trim()) ?? def;
    return v.clamp(min, max);
  }

  // -- build -------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Scaffold(
      backgroundColor: isDark ? Colors.grey.shade900 : Colors.grey.shade50,
      body: SafeArea(
        bottom: false,
        child: AnimatedBuilder(
          animation: _service,
          builder: (context, _) => Column(
            children: [
              _topBar(isDark),
              Expanded(child: _buildBody(isDark)),
            ],
          ),
        ),
      ),
    );
  }

  Widget _topBar(bool isDark) {
    final back =
        _mode == _Mode.config ||
        _mode == _Mode.history ||
        _mode == _Mode.viewing;
    return Padding(
      padding: const EdgeInsets.only(left: 8, right: 8, top: 4),
      child: Row(
        children: [
          _topIcon(
            back ? Icons.chevron_left : Icons.history,
            isDark,
            back ? _goBack : _showHistory,
          ),
          const Spacer(),
          if (!AppNavigation.isDesktop(context)) const ThemeCycleButton(),
          _actionButton(isDark),
        ],
      ),
    );
  }

  Widget _topIcon(IconData icon, bool isDark, VoidCallback onTap) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(8),
        child: Padding(
          padding: const EdgeInsets.all(8),
          child: Icon(
            icon,
            color: isDark ? Colors.white : Colors.black,
            size: 20,
          ),
        ),
      ),
    );
  }

  Widget _actionButton(bool isDark) {
    switch (_mode) {
      case _Mode.config:
        return CenteredButton(
          text: 'Start',
          icon: Icons.play_arrow,
          isPrimary: true,
          disabled: _target.text.trim().isEmpty,
          onTap: _start,
        );
      case _Mode.active:
        if (_service.running) {
          return CenteredButton(
            text: 'Stop',
            icon: Icons.stop,
            backgroundColor: isDark ? Colors.red.shade700 : Colors.red.shade600,
            onTap: () => _service.stop(),
          );
        }
        return CenteredButton(
          text: 'New',
          icon: Icons.add,
          isPrimary: true,
          onTap: () => setState(() => _mode = _Mode.config),
        );
      case _Mode.idle:
      case _Mode.history:
      case _Mode.viewing:
        return CenteredButton(
          text: 'New',
          icon: Icons.add,
          isPrimary: true,
          onTap: () => setState(() => _mode = _Mode.config),
        );
    }
  }

  Widget _buildBody(bool isDark) {
    switch (_mode) {
      case _Mode.idle:
        return _emptyState(isDark);
      case _Mode.history:
        return _historyList(isDark);
      case _Mode.config:
        return _configForm(isDark);
      case _Mode.active:
        final run = _service.active;
        return run == null ? _emptyState(isDark) : _results(run, isDark);
      case _Mode.viewing:
        final run = _viewing;
        return run == null ? _emptyState(isDark) : _results(run, isDark);
    }
  }

  Widget _emptyState(bool isDark) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.handyman_outlined,
            size: 32,
            color: isDark ? Colors.grey.shade700 : Colors.grey.shade300,
          ),
          const SizedBox(height: 12),
          TDText(
            'No tool running',
            font: TDTheme.of(context).fontTitleMedium,
            textColor: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
            fontWeight: FontWeight.w600,
          ),
          const SizedBox(height: 4),
          TDText(
            'Tap New to ping a host or trace its route',
            font: TDTheme.of(context).fontBodySmall,
            textColor: isDark ? Colors.grey.shade500 : Colors.grey.shade500,
          ),
        ],
      ),
    );
  }

  // -- history -------------------------------------------------------------------

  Widget _historyList(bool isDark) {
    final runs = _service.runs;
    if (runs.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.history,
              size: 32,
              color: isDark ? Colors.grey.shade700 : Colors.grey.shade300,
            ),
            const SizedBox(height: 12),
            TDText(
              'No previous runs',
              font: TDTheme.of(context).fontTitleMedium,
              textColor: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
              fontWeight: FontWeight.w600,
            ),
            const SizedBox(height: 4),
            TDText(
              'Finished ping and route jobs land here',
              font: TDTheme.of(context).fontBodySmall,
              textColor: isDark ? Colors.grey.shade500 : Colors.grey.shade500,
            ),
          ],
        ),
      );
    }
    final subColor = isDark ? Colors.grey.shade400 : Colors.grey.shade600;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Row(
          children: [
            TDText(
              '${runs.length} previous run${runs.length == 1 ? '' : 's'}',
              font: TDTheme.of(context).fontBodySmall,
              textColor: subColor,
            ),
            const Spacer(),
            Material(
              color: Colors.transparent,
              child: InkWell(
                onTap: () => _service.clearHistory(),
                borderRadius: BorderRadius.circular(8),
                child: Padding(
                  padding: const EdgeInsets.all(8),
                  child: Icon(
                    Icons.delete_outline,
                    size: 18,
                    color: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
                  ),
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        for (final run in runs) _historyCard(run, isDark),
      ],
    );
  }

  Widget _historyCard(ToolRun run, bool isDark) {
    final themeColor = theme_manager.ThemeManager().themeColor;
    final subColor = isDark ? Colors.grey.shade400 : Colors.grey.shade600;
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
          onTap: () => setState(() {
            _viewing = run;
            _mode = _Mode.viewing;
          }),
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
                    run.kind == ToolKind.ping
                        ? Icons.network_ping
                        : Icons.alt_route,
                    size: 20,
                    color: themeColor,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      TDText(
                        '${run.kind == ToolKind.ping ? 'Ping' : 'Route'} ${run.target}',
                        font: TDTheme.of(context).fontBodyMedium,
                        textColor: isDark ? Colors.white : Colors.black,
                        fontWeight: FontWeight.w600,
                        overflow: TextOverflow.ellipsis,
                      ),
                      TDText(
                        '${run.detail} · ${_fmtTime(run.startedAt)}',
                        font: TDTheme.of(context).fontBodySmall,
                        textColor: subColor,
                        overflow: TextOverflow.ellipsis,
                      ),
                      TDText(
                        _runSummary(run),
                        font: TDTheme.of(context).fontBodySmall,
                        textColor: subColor,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                Material(
                  color: Colors.transparent,
                  child: InkWell(
                    onTap: () => _service.deleteRun(run),
                    borderRadius: BorderRadius.circular(8),
                    child: Padding(
                      padding: const EdgeInsets.all(8),
                      child: Icon(
                        Icons.delete_outline,
                        size: 18,
                        color: subColor,
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  String _runSummary(ToolRun run) {
    if (run.status == 'error') return 'Failed: ${run.error ?? 'unknown'}';
    if (run.status == 'stopped') return 'Stopped';
    if (run.kind == ToolKind.ping) {
      if (run.received == null || run.sent == null) return 'Finished';
      return '${run.received}/${run.sent} replies'
          '${run.avgMs != null ? ' · avg ${run.avgMs!.toStringAsFixed(1)} ms' : ''}';
    }
    if (run.reached == true) {
      return 'Reached ${run.resolvedIp ?? run.target}'
          '${run.hopsDone != null ? ' in ${run.hopsDone} hops' : ''}';
    }
    return 'Not reached${run.hopsDone != null ? ' (${run.hopsDone} hops)' : ''}';
  }

  // -- config form ---------------------------------------------------------------

  Widget _configForm(bool isDark) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        _fieldLabel('Target', isDark),
        const SizedBox(height: 6),
        SquircleInput(
          controller: _target,
          hintText: 'Domain or IP address',
          onSubmitted: (_) => _start(),
        ),
        const SizedBox(height: 14),
        _fieldLabel('Tool', isDark),
        const SizedBox(height: 6),
        TDesignTabSelector(
          tabs: const [
            TDesignTabItem(text: 'Ping', icon: Icon(Icons.network_ping)),
            TDesignTabItem(text: 'Route', icon: Icon(Icons.alt_route)),
          ],
          initialIndex: _tool,
          onTabChanged: (i) => setState(() => _tool = i),
        ),
        const SizedBox(height: 14),
        _fieldLabel(_tool == 0 ? 'Ping options' : 'Route options', isDark),
        const SizedBox(height: 6),
        _optionsCard(isDark),
      ],
    );
  }

  Widget _optionsCard(bool isDark) {
    return Container(
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
      padding: const EdgeInsets.all(12),
      child: _tool == 0 ? _pingOptions(isDark) : _routeOptions(isDark),
    );
  }

  Widget _pingOptions(bool isDark) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _fieldLabel('Protocol', isDark),
        const SizedBox(height: 6),
        TDesignTabSelector(
          tabs: const [
            TDesignTabItem(text: 'ICMP'),
            TDesignTabItem(text: 'UDP'),
            TDesignTabItem(text: 'TCP'),
          ],
          initialIndex: _proto,
          height: 36,
          onTabChanged: (i) => setState(() {
            _proto = i;
            _portCtl.text = i == 1 ? '7' : '80';
          }),
        ),
        const SizedBox(height: 12),
        _fieldLabel('IP version', isDark),
        const SizedBox(height: 6),
        _ipVersionSelector(),
        const SizedBox(height: 12),
        if (_proto != 0) ...[
          _fieldLabel('Port', isDark),
          const SizedBox(height: 6),
          SquircleInput(
            controller: _portCtl,
            hintText: _proto == 1 ? '7' : '80',
            keyboardType: TextInputType.number,
          ),
          const SizedBox(height: 12),
        ],
        _fieldLabel('Pings', isDark),
        const SizedBox(height: 6),
        SquircleInput(
          controller: _countCtl,
          hintText: '5',
          keyboardType: TextInputType.number,
        ),
        const SizedBox(height: 12),
        _fieldLabel('Probe delay (ms)', isDark),
        const SizedBox(height: 6),
        SquircleInput(
          controller: _delayCtl,
          hintText: '1000',
          keyboardType: TextInputType.number,
        ),
        const SizedBox(height: 12),
        _fieldLabel('Payload size (bytes)', isDark),
        const SizedBox(height: 6),
        SquircleInput(
          controller: _payloadCtl,
          hintText: '56',
          keyboardType: TextInputType.number,
        ),
        const SizedBox(height: 8),
        _switchRow(
          "Don't fragment",
          _dontFragment,
          isDark,
          (v) => setState(() => _dontFragment = v),
        ),
        _switchRow(
          'Audible',
          _audible,
          isDark,
          (v) => setState(() => _audible = v),
        ),
      ],
    );
  }

  Widget _routeOptions(bool isDark) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _fieldLabel('IP version', isDark),
        const SizedBox(height: 6),
        _ipVersionSelector(),
        const SizedBox(height: 12),
        _fieldLabel('Max hops', isDark),
        const SizedBox(height: 6),
        SquircleInput(
          controller: _maxHopsCtl,
          hintText: '30',
          keyboardType: TextInputType.number,
        ),
        const SizedBox(height: 12),
        _fieldLabel('Probes per hop', isDark),
        const SizedBox(height: 6),
        SquircleInput(
          controller: _probesCtl,
          hintText: '3',
          keyboardType: TextInputType.number,
        ),
        const SizedBox(height: 12),
        _fieldLabel('Max delay per probe (ms)', isDark),
        const SizedBox(height: 6),
        SquircleInput(
          controller: _maxDelayCtl,
          hintText: '2000',
          keyboardType: TextInputType.number,
        ),
        const SizedBox(height: 12),
        _fieldLabel('Delay between probes (ms)', isDark),
        const SizedBox(height: 6),
        SquircleInput(
          controller: _minDelayCtl,
          hintText: '100',
          keyboardType: TextInputType.number,
        ),
        const SizedBox(height: 8),
        _switchRow(
          'UDP probes',
          _udpProbes,
          isDark,
          (v) => setState(() => _udpProbes = v),
        ),
      ],
    );
  }

  Widget _ipVersionSelector() {
    return TDesignTabSelector(
      tabs: const [
        TDesignTabItem(text: 'Auto'),
        TDesignTabItem(text: 'IPv4'),
        TDesignTabItem(text: 'IPv6'),
      ],
      initialIndex: _ipVersion,
      height: 36,
      onTabChanged: (i) => setState(() => _ipVersion = i),
    );
  }

  Widget _fieldLabel(String text, bool isDark) {
    return TDText(
      text,
      font: TDTheme.of(context).fontBodySmall,
      textColor: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
      fontWeight: FontWeight.w600,
    );
  }

  Widget _switchRow(
    String label,
    bool value,
    bool isDark,
    ValueChanged<bool> onChanged,
  ) {
    final themeColor = theme_manager.ThemeManager().themeColor;
    return Row(
      children: [
        TDText(
          label,
          font: TDTheme.of(context).fontBodyMedium,
          textColor: isDark ? Colors.white : Colors.black87,
        ),
        const Spacer(),
        Switch(
          value: value,
          onChanged: onChanged,
          activeThumbColor: themeColor,
        ),
      ],
    );
  }

  // -- results -----------------------------------------------------------------

  Widget _results(ToolRun run, bool isDark) {
    final subColor = isDark ? Colors.grey.shade400 : Colors.grey.shade600;
    return ListView(
      controller: _scroll,
      padding: const EdgeInsets.all(16),
      children: [
        _runHeader(run, isDark),
        for (final note in run.notes)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: TDText(
              note,
              font: TDTheme.of(context).fontBodySmall,
              textColor: isDark
                  ? Colors.orange.shade300
                  : Colors.orange.shade800,
            ),
          ),
        const SizedBox(height: 8),
        if (run.kind == ToolKind.ping)
          for (final p in run.pings) _pingRow(p, isDark)
        else
          for (final h in run.hops) _hopRow(h, isDark),
        if (!run.running) ...[
          const SizedBox(height: 12),
          _summaryCard(run, isDark),
        ] else if (run.pings.isEmpty && run.hops.isEmpty) ...[
          const SizedBox(height: 16),
          Center(
            child: TDText(
              'Probing…',
              font: TDTheme.of(context).fontBodySmall,
              textColor: subColor,
            ),
          ),
        ],
      ],
    );
  }

  Widget _runHeader(ToolRun run, bool isDark) {
    final themeColor = theme_manager.ThemeManager().themeColor;
    final subColor = isDark ? Colors.grey.shade400 : Colors.grey.shade600;
    final title = run.kind == ToolKind.ping ? 'Ping' : 'Route';
    return Container(
      padding: const EdgeInsets.all(12),
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
              run.kind == ToolKind.ping ? Icons.network_ping : Icons.alt_route,
              size: 20,
              color: themeColor,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                TDText(
                  '$title ${run.target}',
                  font: TDTheme.of(context).fontBodyMedium,
                  textColor: isDark ? Colors.white : Colors.black,
                  fontWeight: FontWeight.w600,
                ),
                TDText(
                  [
                    if (run.resolvedIp != null && run.resolvedIp != run.target)
                      run.resolvedIp!,
                    run.detail,
                  ].join(' · '),
                  font: TDTheme.of(context).fontBodySmall,
                  textColor: subColor,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          const SizedBox(width: 8),
          _statusChip(run, isDark),
        ],
      ),
    );
  }

  Widget _statusChip(ToolRun run, bool isDark) {
    final (label, color) = switch (run.status) {
      'running' => ('Running', theme_manager.ThemeManager().themeColor),
      'stopped' => (
        'Stopped',
        isDark ? Colors.grey.shade400 : Colors.grey.shade600,
      ),
      'error' => ('Error', isDark ? Colors.red.shade300 : Colors.red.shade600),
      _ => ('Done', isDark ? Colors.green.shade300 : Colors.green.shade600),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(6),
      ),
      child: TDText(
        label,
        font: TDTheme.of(context).fontBodySmall,
        textColor: color,
        fontWeight: FontWeight.w600,
      ),
    );
  }

  Widget _pingRow(PingProbe p, bool isDark) {
    final subColor = isDark ? Colors.grey.shade400 : Colors.grey.shade600;
    final titleColor = isDark ? Colors.white : Colors.black87;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          SizedBox(
            width: 32,
            child: TDText(
              '${p.seq + 1}',
              font: TDTheme.of(context).fontBodySmall,
              textColor: subColor,
            ),
          ),
          Expanded(
            child: TDText(
              p.timeout
                  ? 'Request timed out'
                  : [
                      p.from ?? '',
                      if (p.status != null) '(${p.status})',
                      if (p.ttl != null) 'ttl=${p.ttl}',
                    ].join(' ').trim(),
              font: TDTheme.of(context).fontBodyMedium,
              textColor: p.timeout ? subColor : titleColor,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          TDText(
            p.timeout ? '*' : '${p.rttMs?.toStringAsFixed(1) ?? '—'} ms',
            font: TDTheme.of(context).fontBodyMedium,
            textColor: p.timeout ? subColor : titleColor,
            fontWeight: FontWeight.w600,
          ),
        ],
      ),
    );
  }

  Widget _hopRow(RouteHop hop, bool isDark) {
    final subColor = isDark ? Colors.grey.shade400 : Colors.grey.shade600;
    final titleColor = isDark ? Colors.white : Colors.black87;
    final answered = hop.probes.where((p) => p.ip != null).toList();
    final ip = answered.isNotEmpty ? answered.first.ip! : '* * *';
    final hostname = answered
        .map((p) => p.hostname)
        .where((h) => h != null)
        .firstOrNull;
    final times = hop.probes
        .map((p) => p.rttMs != null ? p.rttMs!.toStringAsFixed(1) : '*')
        .join(' · ');
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 32,
            child: TDText(
              '${hop.number}',
              font: TDTheme.of(context).fontBodySmall,
              textColor: subColor,
            ),
          ),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                TDText(
                  hostname != null ? '$hostname ($ip)' : ip,
                  font: TDTheme.of(context).fontBodyMedium,
                  textColor: answered.isEmpty ? subColor : titleColor,
                  fontWeight: FontWeight.w600,
                  overflow: TextOverflow.ellipsis,
                ),
                TDText(
                  hostname != null ? times : '$times ms',
                  font: TDTheme.of(context).fontBodySmall,
                  textColor: subColor,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _summaryCard(ToolRun run, bool isDark) {
    final subColor = isDark ? Colors.grey.shade400 : Colors.grey.shade600;
    final titleColor = isDark ? Colors.white : Colors.black87;
    final lines = run.kind == ToolKind.ping
        ? [
            if (run.sent != null)
              '${run.sent} sent · ${run.received ?? 0} received'
                  '${run.lossPct != null ? ' · ${run.lossPct!.toStringAsFixed(0)}% loss' : ''}',
            if (run.minMs != null)
              'min ${run.minMs!.toStringAsFixed(1)} · '
                  'avg ${run.avgMs!.toStringAsFixed(1)} · '
                  'max ${run.maxMs!.toStringAsFixed(1)} ms',
          ]
        : [
            run.reached == true
                ? 'Reached ${run.resolvedIp ?? run.target}'
                      '${run.hopsDone != null ? ' in ${run.hopsDone} hops' : ''}'
                : 'Destination not reached'
                      '${run.hopsDone != null ? ' after ${run.hopsDone} hops' : ''}',
          ];
    if (run.status == 'error' && run.error != null) {
      lines.add(run.error!);
    }
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: isDark ? Colors.grey.shade800 : Colors.white,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: isDark ? Colors.grey.shade700 : Colors.grey.shade200,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          for (final line in lines)
            TDText(
              line,
              font: TDTheme.of(context).fontBodyMedium,
              textColor: run.status == 'error' ? subColor : titleColor,
            ),
        ],
      ),
    );
  }

  String _fmtTime(DateTime t) {
    final d = t.toLocal();
    String two(int v) => v.toString().padLeft(2, '0');
    final today = DateTime.now();
    final sameDay =
        d.year == today.year && d.month == today.month && d.day == today.day;
    final hm = '${two(d.hour)}:${two(d.minute)}';
    return sameDay ? hm : '${two(d.month)}-${two(d.day)} $hm';
  }
}
