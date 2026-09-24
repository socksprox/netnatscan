/// Windows ping/route engine — the counterpart of the Swift ToolEngine
/// in NetworkPlugin.swift. Produces the same `netnatscan/tools_events`
/// maps ({type: start|reply|timeout|note|hop|hopName|done}) through a
/// broadcast stream instead of an EventChannel.
///
/// Jobs run in a spawned isolate because the ICMP helpers block. Stop is
/// cooperative: a control message flips a flag the job polls between
/// wait slices, and pending async echo calls are always drained before
/// their buffers are freed — killing a job while an IcmpSendEcho2 write
/// is in flight would corrupt the heap.
library;

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

import 'win32_ffi.dart' as w;

class Win32ToolEngine {
  Win32ToolEngine._();
  static final instance = Win32ToolEngine._();

  final _events = StreamController<Map<String, dynamic>>.broadcast();
  Stream<Map<String, dynamic>> get events => _events.stream;

  Isolate? _job;
  SendPort? _control;
  ReceivePort? _port;
  int _jobId = 0;

  Future<Map<String, Object?>> start(String method, Map args) async {
    stop();
    final host = (args['host'] as String? ?? '').trim();
    if (host.isEmpty) {
      return {'ok': false, 'message': 'Missing target host'};
    }
    _jobId = args['job'] is int ? args['job'] as int : _jobId + 1;
    final port = ReceivePort();
    _port = port;
    port.listen((msg) {
      if (msg is SendPort) {
        _control = msg;
        return;
      }
      if (msg is! Map) return;
      final e = Map<String, dynamic>.from(msg);
      if (e['type'] == 'done') _job = null;
      _events.add(e);
    });
    _job = await Isolate.spawn(
      _toolMain,
      {'send': port.sendPort, 'method': method, 'args': args},
      errorsAreFatal: false,
    );
    return {'ok': true};
  }

  void stop() {
    final job = _job;
    _job = null;
    if (job != null) {
      // Ask the job to cancel itself; it drains in-flight async probes
      // and exits. A hard kill is only a fallback — a killed isolate
      // could leave a pending native echo writing into freed memory.
      _control?.send('cancel');
      _events.add({'type': 'done', 'reason': 'stopped', 'job': _jobId});
      Timer(const Duration(seconds: 1), () => job.kill());
    }
    _control = null;
    _port?.close();
    _port = null;
  }
}

// -- job isolate -----------------------------------------------------------------

bool _cancelled = false;

Future<void> _toolMain(Map init) async {
  final send = init['send'] as SendPort;
  final method = init['method'] as String;
  final args = Map<String, dynamic>.from(init['args'] as Map);
  final jobId = (args['job'] as num?)?.toInt() ?? 0;

  // Control channel back to the engine: 'cancel' sets _cancelled. The
  // flag is polled between <=50ms wait slices so cancellation lands even
  // while a native wait is outstanding.
  final control = ReceivePort();
  control.listen((_) => _cancelled = true);
  send.send(control.sendPort);

  void emit(Map<String, Object?> e) =>
      send.send(<String, Object?>{...e, 'job': jobId});
  void emitError(String m) =>
      emit({'type': 'done', 'reason': 'error', 'message': m});

  final host = (args['host'] as String? ?? '').trim();
  final family = args['ipVersion'] as String? ?? 'auto';
  final audible = args['audible'] == true;

  List<InternetAddress> addrs;
  try {
    addrs = await InternetAddress.lookup(
      host,
      type: switch (family) {
        'ipv4' => InternetAddressType.IPv4,
        'ipv6' => InternetAddressType.IPv6,
        _ => InternetAddressType.any,
      },
    );
  } catch (_) {
    emitError("Could not resolve '$host'");
    return;
  }
  if (addrs.isEmpty) {
    emitError("Could not resolve '$host'");
    return;
  }
  // 'auto' prefers IPv4, matching the native side.
  addrs.sort((a, b) => (a.type == InternetAddressType.IPv4 ? 0 : 1)
      .compareTo(b.type == InternetAddressType.IPv4 ? 0 : 1));
  final dst = addrs.first;
  final v6 = dst.type == InternetAddressType.IPv6;

  if (method == 'startRoute') {
    await _routeJob(emit, dst, host, v6, args, audible);
  } else {
    await _pingJob(emit, emitError, dst, host, v6, args, audible);
  }
}

void _beep() {
  try {
    w.messageBeep();
  } catch (_) {}
}

/// Numeric scope id from a `%zone` suffix in an address literal.
int _scopeIdOf(InternetAddress addr) {
  final i = addr.address.indexOf('%');
  if (i < 0) return 0;
  return int.tryParse(addr.address.substring(i + 1)) ?? 0;
}

void _emitReply(void Function(Map<String, Object?>) emit, int seq,
    String from, double rtt, String? status, bool audible,
    {int? ttl}) {
  emit({
    'type': 'reply',
    'seq': seq,
    'from': from,
    'ttl': ?ttl,
    'rttMs': rtt,
    'status': ?status,
  });
  if (audible) _beep();
}

void _finishPing(void Function(Map<String, Object?>) emit, int sent,
    List<double> rtts, String reason) {
  emit({
    'type': 'done',
    'reason': reason,
    'sent': sent,
    'received': rtts.length,
    'lossPct': sent > 0 ? (sent - rtts.length) / sent * 100 : 0.0,
    if (rtts.isNotEmpty) ...{
      'minMs': rtts.reduce((a, b) => a < b ? a : b),
      'maxMs': rtts.reduce((a, b) => a > b ? a : b),
      'avgMs': rtts.reduce((a, b) => a + b) / rtts.length,
    },
  });
}

// -- async echo primitives --------------------------------------------------------

/// One echo probe's outstanding state.
final class _Probe {
  final bool v6;
  int event = 0;
  Pointer<Uint8> reply = nullptr;
  _EchoResult? result; // set once resolved
  _Probe({required this.v6});
}

sealed class _EchoResult {
  const _EchoResult();
}

final class _EchoReply extends _EchoResult {
  final String? from;
  final double? rttMs;
  final int? ttl;
  const _EchoReply(this.from, this.rttMs, this.ttl);
}

final class _EchoTimeout extends _EchoResult {
  const _EchoTimeout();
}

final class _EchoError extends _EchoResult {
  final int status;
  const _EchoError(this.status);
}

/// Fires one async echo on [handle]; [v6] picks the address family.
/// [ttl] bounds the probe for route jobs; null means a full ping.
/// The returned [_Probe]'s result is already set if the call completed
/// inline or the send failed ([_EchoError]).
_Probe _fireEcho(
    Allocator arena,
    int handle,
    bool v6,
    InternetAddress dst,
    int destV4,
    Pointer<w.SOCKADDR_IN6> dstSa,
    Pointer<w.SOCKADDR_IN6> srcSa,
    int payload,
    int? ttl,
    int timeout,
    bool dontFrag) {
  final req = arena<Uint8>(payload.clamp(0, 65535));
  for (var i = 0; i < payload; i++) {
    req[i] = i & 0xff;
  }
  final opt = arena<w.IP_OPTION_INFORMATION>();
  opt.ref
    ..Ttl = ttl ?? 128
    ..Tos = 0
    ..Flags = dontFrag ? w.ipFlagDf : 0
    ..OptionsSize = 0
    ..OptionsData = nullptr;
  final replySize = v6
      ? sizeOf<w.ICMPV6_ECHO_REPLY>() + payload + 8
      : sizeOf<w.ICMP_ECHO_REPLY>() + payload + 8;
  final reply = arena<Uint8>(replySize);
  final event = w.createEvent();
  final r = v6
      ? w.icmp6SendEcho2Async(
          handle, event, srcSa, dstSa, req, payload, opt, reply, replySize,
          timeout)
      : w.icmpSendEcho2(
          handle, event, destV4, req, payload, opt, reply, replySize,
          timeout);
  final probe = _Probe(v6: v6)
    ..event = event
    ..reply = reply;
  // r > 0 = completed inline. r == 0 normally means ERROR_IO_PENDING —
  // but the FFI trampoline can clobber GetLastError before we read it,
  // so a failed send is indistinguishable from pending. Treating 0 as
  // pending is safe: a real failure never signals the event, so the
  // probe just resolves as a timeout at the deadline.
  if (r > 0) probe.result = _parseEcho(reply, v6);
  return probe;
}

_EchoResult _parseEcho(Pointer<Uint8> reply, bool v6) =>
    v6 ? _parse6(reply) : _parse4(reply);

_EchoResult _parse4(Pointer<Uint8> reply) {
  final r = reply.cast<w.ICMP_ECHO_REPLY>().ref;
  if (r.Status == w.ipSuccess || r.Status == w.ipTtlExpiredTransit) {
    final a = r.Address;
    return _EchoReply(
        '${a & 255}.${(a >> 8) & 255}.${(a >> 16) & 255}.${(a >> 24) & 255}',
        r.RoundTripTime.toDouble(),
        r.Options.Ttl);
  }
  if (r.Status == w.ipReqTimedOut) return const _EchoTimeout();
  return _EchoError(r.Status);
}

_EchoResult _parse6(Pointer<Uint8> reply) {
  final r = reply.cast<w.ICMPV6_ECHO_REPLY>().ref;
  if (r.Status == w.ipSuccess || r.Status == w.ipTtlExpiredTransit) {
    final ip = w.inetNtopString(w.afInet6, reply);
    return _EchoReply(ip ?? '?', r.RoundTripTime.toDouble(), null);
  }
  if (r.Status == w.ipReqTimedOut) return const _EchoTimeout();
  return _EchoError(r.Status);
}

/// Waits for [probe]'s event in <=50ms slices so the cancel flag is
/// polled even while a native wait is outstanding. Returns true once the
/// probe resolved (sync, signalled, or timed out at the deadline).
bool _awaitProbe(Allocator arena, _Probe probe, int timeoutMs) {
  if (probe.result != null) return true;
  final ev = arena<IntPtr>(1)..value = probe.event;
  final deadline = DateTime.now().add(Duration(milliseconds: timeoutMs));
  while (!_cancelled) {
    final remain = deadline.difference(DateTime.now()).inMilliseconds;
    if (remain <= 0) break;
    final r = w.waitForObjects(ev, 1, remain.clamp(0, 50));
    if (r == 0) {
      // WAIT_OBJECT_0 — the reply buffer is complete now.
      probe.result = _parseEcho(probe.reply, probe.v6);
      return true;
    }
    if (r == 0x102 /* WAIT_TIMEOUT */) continue;
    if (r == 0xFFFFFFFF /* WAIT_FAILED */) break;
  }
  // Deadline or cancel: the call may still complete asynchronously, but
  // we keep the event open until _drainProbes has confirmed the write.
  return probe.result != null;
}

/// Drains every outstanding probe before its arena is freed — the OS
/// writes the reply buffer asynchronously, so freeing early corrupts
/// the heap.
void _drainProbes(Allocator arena, List<_Probe?> probes, int graceMs) {
  final pending = [
    for (var i = 0; i < probes.length; i++)
      if (probes[i] != null && probes[i]!.result == null) i,
  ];
  if (pending.isEmpty) return;
  final deadline = DateTime.now().add(Duration(milliseconds: graceMs));
  for (final i in pending) {
    final ev = arena<IntPtr>(1)..value = probes[i]!.event;
    var r = 0x102;
    while (!_cancelled) {
      final remain = deadline.difference(DateTime.now()).inMilliseconds;
      if (remain <= 0) break;
      r = w.waitForObjects(ev, 1, remain.clamp(0, 50));
      if (r != 0x102) break;
    }
    if (r == 0) {
      probes[i]!.result = _parseEcho(probes[i]!.reply, probes[i]!.v6);
    }
  }
  for (final p in probes) {
    if (p != null) w.closeHandle(p.event);
  }
}

// -- ping ---------------------------------------------------------------------

Future<void> _pingJob(
    void Function(Map<String, Object?>) emit,
    void Function(String) emitError,
    InternetAddress dst,
    String host,
    bool v6,
    Map<String, dynamic> args,
    bool audible) async {
  final proto = args['protocol'] as String? ?? 'icmp';
  final count = (args['count'] as num?)?.toInt() ?? 5;
  final interval = (args['intervalMs'] as num?)?.toInt() ?? 1000;
  final payload = (args['payloadBytes'] as num?)?.toInt() ?? 56;
  final port = (args['port'] as num?)?.toInt() ?? (proto == 'udp' ? 7 : 80);
  final dontFrag = args['dontFragment'] == true;

  emit({
    'type': 'start',
    'tool': 'ping',
    'target': host,
    'resolved': dst.address,
    'detail': args['detail'] as String? ?? '',
  });

  switch (proto) {
    case 'udp':
      _pingUdp(emit, dst, v6, count, interval, port, audible);
    case 'tcp':
      await _pingTcp(emit, dst, count, interval, port, audible);
    default:
      _pingIcmp(emit, dst, v6, count, interval, payload, dontFrag, audible);
  }
}

/// ICMP echo via IcmpSendEcho2 — each probe waits up to `interval` ms in
/// cancel-pollable slices, which doubles as the probe cadence.
void _pingIcmp(
    void Function(Map<String, Object?>) emit,
    InternetAddress dst,
    bool v6,
    int count,
    int interval,
    int payload,
    bool dontFrag,
    bool audible) {
  final handle = v6 ? w.icmp6CreateFile() : w.icmpCreateFile();
  if (handle == 0 || handle == -1) {
    emit({'type': 'done', 'reason': 'error', 'message': 'ICMP failed'});
    return;
  }
  try {
    final rtts = <double>[];
    var sent = 0;
    var destV4 = 0;
    if (!v6) {
      final a = dst.rawAddress;
      destV4 = a[0] | a[1] << 8 | a[2] << 16 | a[3] << 24;
    }
    for (var seq = 0; seq < count && !_cancelled; seq++) {
      final r = using((arena) {
        final dstSa =
            v6 ? w.sockaddrIn6(arena, dst, scopeId: _scopeIdOf(dst)) : nullptr;
        final srcSa =
            v6 ? w.sockaddrIn6(arena, InternetAddress('::')) : nullptr;
        final probe = _fireEcho(arena, handle, v6, dst, destV4, dstSa,
            srcSa, payload, null, interval, dontFrag);
        _awaitProbe(arena, probe, interval);
        _drainProbes(arena, [probe], 200);
        return probe.result ?? const _EchoTimeout();
      });
      sent++;
      switch (r) {
        case _EchoReply(:final from, :final rttMs):
          if (from != null && rttMs != null) {
            _emitReply(emit, seq, from, rttMs, null, audible, ttl: r.ttl);
            rtts.add(rttMs);
          } else {
            emit({'type': 'timeout', 'seq': seq});
          }
        case _EchoTimeout():
          emit({'type': 'timeout', 'seq': seq});
        case _EchoError(:final status):
          emit({
            'type': 'note',
            'message': 'seq $seq: ${_icmpStatus(status)}'
          });
      }
    }
    _finishPing(
        emit, sent, rtts, _cancelled ? 'stopped' : 'finished');
  } finally {
    w.icmpCloseHandle(handle);
  }
}

/// TCP ping — a completed or refused connect both prove the host is up.
Future<void> _pingTcp(
    void Function(Map<String, Object?>) emit,
    InternetAddress dst,
    int count,
    int interval,
    int port,
    bool audible) async {
  final rtts = <double>[];
  var sent = 0;
  for (var seq = 0; seq < count && !_cancelled; seq++) {
    final sw = Stopwatch()..start();
    var answered = false;
    sent++;
    try {
      final s = await Socket.connect(
          dst.address, port,
          timeout: Duration(milliseconds: interval));
      s.destroy();
      final rtt = sw.elapsedMilliseconds.toDouble();
      _emitReply(emit, seq, dst.address, rtt, 'connected', audible);
      rtts.add(rtt);
      answered = true;
    } on SocketException catch (e) {
      final code = e.osError?.errorCode;
      if (code == 61 || code == 10061 || code == 54 || code == 10054) {
        final rtt = sw.elapsedMilliseconds.toDouble();
        _emitReply(emit, seq, dst.address, rtt, 'reset', audible);
        rtts.add(rtt);
        answered = true;
      }
    } catch (_) {}
    if (!answered) emit({'type': 'timeout', 'seq': seq});
    final rest = interval - sw.elapsedMilliseconds;
    for (var waited = 0; waited < rest && !_cancelled; waited += 50) {
      await Future.delayed(Duration(milliseconds: (rest - waited).clamp(0, 50)));
    }
  }
  _finishPing(emit, sent, rtts, _cancelled ? 'stopped' : 'finished');
}

/// UDP ping — a datagram to a (usually closed) port; the host's ICMP
/// port-unreachable comes back as WSAECONNRESET on the connected socket,
/// the same shape as ECONNREFUSED on macOS.
void _pingUdp(
    void Function(Map<String, Object?>) emit,
    InternetAddress dst,
    bool v6,
    int count,
    int interval,
    int port,
    bool audible) {
  final rtts = <double>[];
  var sent = 0;
  for (var seq = 0; seq < count && !_cancelled; seq++) {
    final sw = Stopwatch()..start();
    var answered = false;
    using((arena) {
      final fd = w.wsaSocket(v6 ? w.afInet6 : w.afInet, w.sockDgram, 0);
      if (fd <= 0) {
        emit({
          'type': 'note',
          'message': 'UDP socket failed: ${w.wsaGetLastError()}',
        });
        return;
      }
      try {
        final sa = v6
            ? w.sockaddrIn6(arena, dst, scopeId: _scopeIdOf(dst), port: port)
            : _sockaddrIn4(arena, dst, port);
        final saLen = v6 ? 28 : 16;
        if (w.wsaConnect(fd, sa, saLen) != 0) {
          emit({
            'type': 'note',
            'message': 'connect failed: ${w.wsaGetLastError()}',
          });
          return;
        }
        final timeout = arena<Uint32>()..value = interval;
        w.wsaSetsockopt(fd, w.solSocket, w.soRcvtimeo, timeout.cast(), 4);
        final payload = arena<Uint8>(1);
        if (w.wsaSend(fd, payload, 1, 0) < 0) return;
        sent++;
        // Poll recv in slices so cancel stays responsive — recv blocks
        // up to SO_RCVTIMEO otherwise.
        final deadline =
            DateTime.now().add(Duration(milliseconds: interval));
        while (!_cancelled) {
          final remain =
              deadline.difference(DateTime.now()).inMilliseconds;
          if (remain <= 0) break;
          final timeout50 = arena<Uint32>()..value = remain.clamp(0, 50);
          w.wsaSetsockopt(
              fd, w.solSocket, w.soRcvtimeo, timeout50.cast(), 4);
          final buf = arena<Uint8>(64);
          final n = w.wsaRecv(fd, buf, 64, 0);
          final rtt = sw.elapsedMilliseconds.toDouble();
          if (n > 0) {
            _emitReply(emit, seq, dst.address, rtt, 'data', audible);
            rtts.add(rtt);
            answered = true;
            return;
          }
          final err = w.wsaGetLastError();
          if (err == w.wsaEconnreset) {
            _emitReply(
                emit, seq, dst.address, rtt, 'port unreachable', audible);
            rtts.add(rtt);
            answered = true;
            return;
          }
          if (err != w.wsaEtimedout) return; // other error → give up
        }
      } finally {
        w.wsaClose(fd);
      }
    });
    if (!answered) emit({'type': 'timeout', 'seq': seq});
    final rest = interval - sw.elapsedMilliseconds;
    if (rest > 0 && !_cancelled) w.sleepMs(rest.clamp(0, 50));
  }
  _finishPing(emit, sent, rtts, _cancelled ? 'stopped' : 'finished');
}

// -- route ----------------------------------------------------------------------

/// ICMP traceroute — one batched async send per hop via
/// IcmpSendEcho2/Icmp6SendEcho2 events, then collect until every probe
/// answered or maxDelay elapsed. UDP-probe mode falls back to ICMP (raw
/// sockets need admin on Windows, same as the macOS sandbox).
Future<void> _routeJob(
    void Function(Map<String, Object?>) emit,
    InternetAddress dst,
    String host,
    bool v6,
    Map<String, dynamic> args,
    bool audible) async {
  final maxHops = (args['maxHops'] as num?)?.toInt() ?? 30;
  final pph = (args['probesPerHop'] as num?)?.toInt() ?? 3;
  final maxDelay = (args['maxDelayMs'] as num?)?.toInt() ?? 2000;
  final minDelay = (args['minDelayMs'] as num?)?.toInt() ?? 100;
  if (args['udpProbes'] == true) {
    emit({
      'type': 'note',
      'message': 'UDP probes need raw sockets — using ICMP',
    });
  }

  emit({
    'type': 'start',
    'tool': 'route',
    'target': host,
    'resolved': dst.address,
    'detail': args['detail'] as String? ?? '',
  });

  final handle = v6 ? w.icmp6CreateFile() : w.icmpCreateFile();
  if (handle == 0 || handle == -1) {
    emit({'type': 'done', 'reason': 'error', 'message': 'ICMP failed'});
    return;
  }

  final nameCache = <String, String>{};
  var reached = false;
  var hopsDone = 0;

  try {
    var destV4 = 0;
    if (!v6) {
      final a = dst.rawAddress;
      destV4 = a[0] | a[1] << 8 | a[2] << 16 | a[3] << 24;
    }
    for (var hop = 1; hop <= maxHops && !reached && !_cancelled; hop++) {
      // Fire all probes of this hop back-to-back on event handles.
      final results = using((arena) {
        final probes = List<_Probe?>.filled(pph, null);
        final dstSa = v6
            ? w.sockaddrIn6(arena, dst, scopeId: _scopeIdOf(dst))
            : nullptr;
        final srcSa =
            v6 ? w.sockaddrIn6(arena, InternetAddress('::')) : nullptr;
        for (var p = 0; p < pph; p++) {
          probes[p] = _fireEcho(arena, handle, v6, dst, destV4, dstSa,
              srcSa, v6 ? 32 : 24, hop, maxDelay, false);
          if (p + 1 < pph && minDelay > 0) w.sleepMs(minDelay);
        }

        // Collect until all answered or the deadline passes.
        final deadline =
            DateTime.now().add(Duration(milliseconds: maxDelay));
        for (var p = 0; p < pph; p++) {
          final probe = probes[p];
          if (probe == null) continue;
          final remain =
              deadline.difference(DateTime.now()).inMilliseconds;
          if (remain > 0) _awaitProbe(arena, probe, remain);
        }
        // Any probe still pending writes into this arena — wait for it
        // before the arena frees, or the heap is corrupted.
        _drainProbes(arena, probes, 300);
        return [for (var p = 0; p < pph; p++) probes[p]?.result];
      });

      // Map results onto the hop's probe list + emit.
      final probes = <Map<String, Object?>?>[
        for (var p = 0; p < pph; p++)
          switch (results[p]) {
            _EchoReply(from: final f?, :final rttMs) =>
              {'ip': f, 'rttMs': rttMs},
            _ => null,
          },
      ];
      for (final r in results) {
        if (r is _EchoReply && r.from == dst.address) reached = true;
      }
      emit({'type': 'hop', 'hop': hop, 'probes': probes});
      hopsDone = hop;

      // Reverse-DNS the hop IPs (async, off the probe path).
      for (final pr in probes) {
        final ip = pr?['ip'] as String?;
        if (ip == null || nameCache.containsKey(ip)) continue;
        nameCache[ip] = '';
        try {
          final rev = await InternetAddress(ip).reverse();
          if (rev.host.isNotEmpty && rev.host != ip) {
            emit({
              'type': 'hopName',
              'hop': hop,
              'ip': ip,
              'hostname': rev.host,
            });
          }
        } catch (_) {}
      }
    }
  } finally {
    w.icmpCloseHandle(handle);
  }

  emit({
    'type': 'done',
    'reason': _cancelled ? 'stopped' : 'finished',
    'hops': hopsDone,
    'reached': reached,
  });
}

Pointer _sockaddrIn4(Allocator arena, InternetAddress addr, int port) {
  final sa = arena<Uint8>(16);
  sa[0] = w.afInet & 0xff;
  sa[1] = 0;
  sa[2] = (port >> 8) & 0xff; // sin_port is network order
  sa[3] = port & 0xff;
  final a = addr.rawAddress;
  for (var i = 0; i < 4; i++) {
    sa[4 + i] = a[i];
  }
  return sa;
}

String _icmpStatus(int s) => switch (s) {
      11002 => 'destination network unreachable',
      11003 => 'destination host unreachable',
      11004 => 'destination protocol unreachable',
      11005 => 'destination port unreachable',
      11013 => 'TTL expired in transit',
      _ => 'ICMP status $s',
    };
