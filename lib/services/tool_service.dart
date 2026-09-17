import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

/// Which built-in tool produced a run.
enum ToolKind { ping, route }

/// One ping round: a reply with RTT, or a timeout.
class PingProbe {
  final int seq;
  String? from;
  double? rttMs;
  int? ttl;
  String? status; // 'connected', 'reset', 'port unreachable', 'data'
  bool timeout = false;

  PingProbe(this.seq);

  Map<String, dynamic> toJson() => {
    'seq': seq,
    'from': from,
    'rttMs': rttMs,
    'ttl': ttl,
    'status': status,
    'timeout': timeout,
  };

  factory PingProbe.fromJson(Map<String, dynamic> m) =>
      PingProbe((m['seq'] as num).toInt())
        ..from = m['from'] as String?
        ..rttMs = (m['rttMs'] as num?)?.toDouble()
        ..ttl = (m['ttl'] as num?)?.toInt()
        ..status = m['status'] as String?
        ..timeout = m['timeout'] == true;
}

/// One probe toward one route hop — ip/hostname may be absent (no reply).
class HopProbe {
  String? ip;
  String? hostname;
  double? rttMs;

  HopProbe();

  Map<String, dynamic> toJson() => {
    'ip': ip,
    'hostname': hostname,
    'rttMs': rttMs,
  };

  factory HopProbe.fromJson(Map<String, dynamic> m) => HopProbe()
    ..ip = m['ip'] as String?
    ..hostname = m['hostname'] as String?
    ..rttMs = (m['rttMs'] as num?)?.toDouble();
}

/// A route hop (TTL value) with its per-probe results.
class RouteHop {
  final int number;
  final List<HopProbe> probes;

  RouteHop(this.number, this.probes);

  Map<String, dynamic> toJson() => {
    'number': number,
    'probes': probes.map((p) => p.toJson()).toList(),
  };

  factory RouteHop.fromJson(Map<String, dynamic> m) => RouteHop(
    (m['number'] as num).toInt(),
    (m['probes'] as List? ?? const [])
        .whereType<Map>()
        .map((p) => HopProbe.fromJson(Map<String, dynamic>.from(p)))
        .toList(),
  );
}

/// A single tool invocation — live while [status] == 'running', then
/// archived into [ToolService.runs].
class ToolRun {
  ToolRun({
    required this.id,
    required this.kind,
    required this.target,
    required this.startedAt,
    this.detail = '',
  });

  final String id;
  final ToolKind kind;
  final String target;
  String detail; // config summary, e.g. 'ICMP · 5× every 1000 ms · 56 B'
  String? resolvedIp;
  int? jobId;
  final DateTime startedAt;
  DateTime? finishedAt;
  String status = 'running'; // running | finished | stopped | error
  String? error;
  final List<String> notes = [];

  final List<PingProbe> pings = [];
  final List<RouteHop> hops = [];

  // Ping summary.
  int? sent;
  int? received;
  double? lossPct;
  double? minMs;
  double? avgMs;
  double? maxMs;

  // Route summary.
  bool? reached;
  int? hopsDone;

  bool get running => status == 'running';

  Map<String, dynamic> toJson() => {
    'id': id,
    'kind': kind.name,
    'target': target,
    'detail': detail,
    'resolvedIp': resolvedIp,
    'startedAt': startedAt.millisecondsSinceEpoch,
    'finishedAt': finishedAt?.millisecondsSinceEpoch,
    'status': status,
    'error': error,
    'notes': notes,
    'pings': pings.map((p) => p.toJson()).toList(),
    'hops': hops.map((h) => h.toJson()).toList(),
    'sent': sent,
    'received': received,
    'lossPct': lossPct,
    'minMs': minMs,
    'avgMs': avgMs,
    'maxMs': maxMs,
    'reached': reached,
    'hopsDone': hopsDone,
  };

  factory ToolRun.fromJson(Map<String, dynamic> m) =>
      ToolRun(
          id: m['id'] as String? ?? '',
          kind: m['kind'] == 'route' ? ToolKind.route : ToolKind.ping,
          target: m['target'] as String? ?? '',
          startedAt: DateTime.fromMillisecondsSinceEpoch(
            (m['startedAt'] as num?)?.toInt() ?? 0,
          ),
          detail: m['detail'] as String? ?? '',
        )
        ..resolvedIp = m['resolvedIp'] as String?
        ..finishedAt = (m['finishedAt'] as num?)?.toInt() != null
            ? DateTime.fromMillisecondsSinceEpoch(
                (m['finishedAt'] as num).toInt(),
              )
            : null
        ..status = m['status'] as String? ?? 'finished'
        ..error = m['error'] as String?
        ..notes.addAll(
          (m['notes'] as List? ?? const []).map((e) => e.toString()),
        )
        ..pings.addAll(
          (m['pings'] as List? ?? const []).whereType<Map>().map(
            (p) => PingProbe.fromJson(Map<String, dynamic>.from(p)),
          ),
        )
        ..hops.addAll(
          (m['hops'] as List? ?? const []).whereType<Map>().map(
            (h) => RouteHop.fromJson(Map<String, dynamic>.from(h)),
          ),
        )
        ..sent = (m['sent'] as num?)?.toInt()
        ..received = (m['received'] as num?)?.toInt()
        ..lossPct = (m['lossPct'] as num?)?.toDouble()
        ..minMs = (m['minMs'] as num?)?.toDouble()
        ..avgMs = (m['avgMs'] as num?)?.toDouble()
        ..maxMs = (m['maxMs'] as num?)?.toDouble()
        ..reached = m['reached'] as bool?
        ..hopsDone = (m['hopsDone'] as num?)?.toInt();
}

/// Runs ping/route jobs against the native tool engine
/// (MethodChannel `netnatscan/network` for start/stop, EventChannel
/// `netnatscan/tools_events` for streamed replies/hops) and keeps a
/// persisted history of finished runs.
class ToolService extends ChangeNotifier {
  static const _methods = MethodChannel('netnatscan/network');
  static const _events = EventChannel('netnatscan/tools_events');
  static const _historyCap = 50;

  ToolRun? active;
  final List<ToolRun> runs = [];
  bool historyLoaded = false;

  bool _disposed = false;
  StreamSubscription<dynamic>? _sub;
  int _jobSeq = 0;

  ToolService() {
    // One persistent subscription — events carry a `job` id so stale
    // events from a cancelled job can't corrupt the new active run.
    _sub = _events.receiveBroadcastStream().listen(_onEvent, onError: (_) {});
    loadHistory();
  }

  bool get running => active?.running ?? false;

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _sub?.cancel();
    // Best-effort stop so a native job doesn't outlive the screen.
    _methods.invokeMethod('stopTool').catchError((_) {});
    super.dispose();
  }

  Future<void> startPing(String target, Map<String, Object> config) =>
      _start('startPing', ToolKind.ping, target, config);

  Future<void> startRoute(String target, Map<String, Object> config) =>
      _start('startRoute', ToolKind.route, target, config);

  Future<void> _start(
    String method,
    ToolKind kind,
    String target,
    Map<String, Object> config,
  ) async {
    _archiveActiveAsStopped();
    final jobId = ++_jobSeq;
    final run = ToolRun(
      id: 'run-$jobId-${DateTime.now().millisecondsSinceEpoch}',
      kind: kind,
      target: target,
      startedAt: DateTime.now(),
      detail: config['detail'] as String? ?? '',
    )..jobId = jobId;
    active = run;
    _notify();
    try {
      final res = await _methods.invokeMapMethod<String, dynamic>(method, {
        ...config,
        'host': target,
        'job': jobId,
      });
      if (res?['ok'] == false) {
        _finish(
          run,
          'error',
          error: res?['message'] as String? ?? 'Failed to start',
        );
      }
    } on PlatformException catch (e) {
      _finish(run, 'error', error: e.message ?? e.code);
    } on MissingPluginException {
      _finish(run, 'error', error: 'Native tools unavailable');
    }
  }

  Future<void> stop() async {
    if (!running) return;
    try {
      await _methods.invokeMethod('stopTool');
    } catch (_) {
      _finish(active!, 'stopped');
    }
  }

  // -- event handling ------------------------------------------------------

  void _onEvent(dynamic ev) {
    if (ev is! Map) return;
    final e = Map<String, dynamic>.from(ev);
    final run = active;
    if (run == null) return;
    final job = (e['job'] as num?)?.toInt();
    if (job != null && run.jobId != null && job != run.jobId) return;

    switch (e['type']) {
      case 'start':
        run.resolvedIp = e['resolved'] as String?;
      case 'reply':
        final p = _upsertProbe(run, (e['seq'] as num).toInt());
        p.from = e['from'] as String?;
        p.rttMs = (e['rttMs'] as num?)?.toDouble();
        p.ttl = (e['ttl'] as num?)?.toInt();
        p.status = e['status'] as String?;
        p.timeout = false;
      case 'timeout':
        _upsertProbe(run, (e['seq'] as num).toInt()).timeout = true;
      case 'note':
        run.notes.add('${e['message']}');
      case 'hop':
        _upsertHop(run, e);
      case 'hopName':
        _setHopName(run, e);
      case 'done':
        run.sent = (e['sent'] as num?)?.toInt();
        run.received = (e['received'] as num?)?.toInt();
        run.lossPct = (e['lossPct'] as num?)?.toDouble();
        run.minMs = (e['minMs'] as num?)?.toDouble();
        run.avgMs = (e['avgMs'] as num?)?.toDouble();
        run.maxMs = (e['maxMs'] as num?)?.toDouble();
        run.reached = e['reached'] as bool?;
        run.hopsDone = (e['hops'] as num?)?.toInt();
        _finish(
          run,
          e['reason'] as String? ?? 'finished',
          error: e['message'] as String?,
        );
        return;
    }
    _notify();
  }

  PingProbe _upsertProbe(ToolRun run, int seq) {
    for (final p in run.pings) {
      if (p.seq == seq) return p;
    }
    final p = PingProbe(seq);
    // Keep probes sorted by seq — a late reply can arrive out of order.
    final i = run.pings.indexWhere((q) => q.seq > seq);
    if (i < 0) {
      run.pings.add(p);
    } else {
      run.pings.insert(i, p);
    }
    return p;
  }

  void _upsertHop(ToolRun run, Map<String, dynamic> e) {
    final number = (e['hop'] as num).toInt();
    final probes = (e['probes'] as List? ?? const []).map((p) {
      if (p is Map) {
        return HopProbe()
          ..ip = p['ip'] as String?
          ..rttMs = (p['rttMs'] as num?)?.toDouble();
      }
      return HopProbe();
    }).toList();
    final i = run.hops.indexWhere((h) => h.number == number);
    if (i >= 0) {
      run.hops[i] = RouteHop(number, probes);
    } else {
      run.hops.add(RouteHop(number, probes));
    }
  }

  void _setHopName(ToolRun run, Map<String, dynamic> e) {
    final number = (e['hop'] as num?)?.toInt();
    final ip = e['ip'] as String?;
    final name = e['hostname'] as String?;
    if (number == null || ip == null || name == null) return;
    for (final h in run.hops) {
      if (h.number != number) continue;
      for (final p in h.probes) {
        if (p.ip == ip) p.hostname = name;
      }
    }
  }

  // -- run lifecycle ---------------------------------------------------------

  void _finish(ToolRun run, String status, {String? error}) {
    run.status = status;
    run.error = error;
    run.finishedAt = DateTime.now();
    if (!run.running && !runs.any((r) => r.id == run.id)) {
      runs.insert(0, run);
      if (runs.length > _historyCap) runs.removeRange(_historyCap, runs.length);
      _persist();
    }
    _notify();
  }

  void _archiveActiveAsStopped() {
    final run = active;
    if (run != null && run.running) _finish(run, 'stopped');
  }

  Future<void> deleteRun(ToolRun run) async {
    runs.removeWhere((r) => r.id == run.id);
    _notify();
    await _persist();
  }

  Future<void> clearHistory() async {
    runs.clear();
    _notify();
    await _persist();
  }

  // -- persistence -----------------------------------------------------------

  Future<void> loadHistory() async {
    if (historyLoaded) return;
    historyLoaded = true;
    try {
      final dir = await getApplicationDocumentsDirectory();
      final file = File('${dir.path}/tool_history.json');
      if (await file.exists()) {
        final list = jsonDecode(await file.readAsString());
        if (list is List) {
          runs.addAll(
            list.whereType<Map>().map(
              (m) => ToolRun.fromJson(Map<String, dynamic>.from(m)),
            ),
          );
          _notify();
        }
      }
    } catch (_) {}
  }

  Future<void> _persist() async {
    try {
      final dir = await getApplicationDocumentsDirectory();
      final file = File('${dir.path}/tool_history.json');
      await file.writeAsString(
        jsonEncode(runs.map((r) => r.toJson()).toList()),
      );
    } catch (_) {}
  }
}
