/// Windows ping/route engine — the counterpart of the Swift ToolEngine
/// in NetworkPlugin.swift. Produces the same `netnatscan/tools_events`
/// maps ({type: start|reply|timeout|note|hop|hopName|done}) through a
/// broadcast stream instead of an EventChannel.
///
/// Jobs run in a spawned isolate because the ICMP helpers block
/// (IcmpSendEcho waits up to the timeout per call); stop() kills the
/// isolate — the same semantics as closing the job's sockets on macOS.
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
      job.kill();
      // A killed isolate can't report its own death — synthesize the
      // done event the native cancel path produces.
      _events.add({'type': 'done', 'reason': 'stopped', 'job': _jobId});
    }
    _port?.close();
    _port = null;
  }
}

// -- job isolate -----------------------------------------------------------------

Future<void> _toolMain(Map init) async {
  final send = init['send'] as SendPort;
  final method = init['method'] as String;
  final args = Map<String, dynamic>.from(init['args'] as Map);
  final jobId = (args['job'] as num?)?.toInt() ?? 0;

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

/// ICMP echo via IcmpSendEcho / Icmp6SendEcho2 — each call blocks up to
/// `interval` ms, which doubles as the probe cadence (same semantics as
/// the SOCK_DGRAM loop on macOS).
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
    for (var seq = 0; seq < count; seq++) {
      final r = v6
          ? _echo6(handle, dst, payload, null, interval, dontFrag)
          : _echo4(handle, dst, payload, null, interval, dontFrag);
      sent++;
      switch (r) {
        case _EchoReply(:final from!, :final rttMs!):
          _emitReply(emit, seq, from, rttMs, null, audible, ttl: r.ttl);
          rtts.add(rttMs);
        case _EchoTimeout():
          emit({'type': 'timeout', 'seq': seq});
        case _EchoError(:final status):
          emit({'type': 'note', 'message': 'seq $seq: ${_icmpStatus(status)}'});
      }
    }
    _finishPing(emit, sent, rtts, 'finished');
  } finally {
    w.icmpCloseHandle(handle);
  }
}

/// One blocking echo. [ttl] bounds the probe (route job); null = 128.
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

_EchoResult _echo4(int handle, InternetAddress dst, int payload, int? ttl,
    int timeout, bool dontFrag) {
  return using((arena) {
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
    final replySize = sizeOf<w.ICMP_ECHO_REPLY>() + payload + 8;
    final reply = arena<Uint8>(replySize);
    final addr = dst.rawAddress;
    final dest = addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24;
    final n = w.icmpSendEcho(
        handle, dest, req, payload, opt, reply, replySize, timeout);
    if (n == 0) return const _EchoTimeout();
    final r = reply.cast<w.ICMP_ECHO_REPLY>().ref;
    if (r.Status == w.ipSuccess) {
      final a = r.Address;
      return _EchoReply(
          '${a & 255}.${(a >> 8) & 255}.${(a >> 16) & 255}.${(a >> 24) & 255}',
          r.RoundTripTime.toDouble(),
          r.Options.Ttl);
    }
    if (r.Status == w.ipReqTimedOut) return const _EchoTimeout();
    if (r.Status == w.ipTtlExpiredTransit) {
      final a = r.Address;
      return _EchoReply(
          '${a & 255}.${(a >> 8) & 255}.${(a >> 16) & 255}.${(a >> 24) & 255}',
          r.RoundTripTime.toDouble(),
          null);
    }
    return _EchoError(r.Status);
  });
}

_EchoResult _echo6(int handle, InternetAddress dst, int payload, int? ttl,
    int timeout, bool dontFrag) {
  return using((arena) {
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
    final replySize = sizeOf<w.ICMPV6_ECHO_REPLY>() + payload + 8;
    final reply = arena<Uint8>(replySize);
    final src = w.sockaddrIn6(arena, InternetAddress('::'));
    final dstSa = w.sockaddrIn6(arena, dst, scopeId: _scopeIdOf(dst));
    final n = w.icmp6SendEcho2(
        handle, src, dstSa, req, payload, opt, reply, replySize, timeout);
    if (n == 0) return const _EchoTimeout();
    final r = reply.cast<w.ICMPV6_ECHO_REPLY>().ref;
    if (r.Status == w.ipSuccess || r.Status == w.ipTtlExpiredTransit) {
      final addrBytes = reply.cast<Uint8>();
      final ip = w.inetNtopString(w.afInet6, addrBytes);
      return _EchoReply(ip ?? '?', r.RoundTripTime.toDouble(), null);
    }
    if (r.Status == w.ipReqTimedOut) return const _EchoTimeout();
    return _EchoError(r.Status);
  });
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
  for (var seq = 0; seq < count; seq++) {
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
    if (rest > 0) await Future.delayed(Duration(milliseconds: rest));
  }
  _finishPing(emit, sent, rtts, 'finished');
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
  for (var seq = 0; seq < count; seq++) {
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
            ? w.sockaddrIn6(arena, dst,
                scopeId: _scopeIdOf(dst), port: port)
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
        w.wsaSetsockopt(
            fd, w.solSocket, w.soRcvtimeo, timeout.cast(), 4);
        final payload = arena<Uint8>(1);
        if (w.wsaSend(fd, payload, 1, 0) < 0) return;
        sent++;
        final buf = arena<Uint8>(64);
        final n = w.wsaRecv(fd, buf, 64, 0);
        final rtt = sw.elapsedMilliseconds.toDouble();
        if (n > 0) {
          _emitReply(emit, seq, dst.address, rtt, 'data', audible);
          rtts.add(rtt);
          answered = true;
        } else {
          final err = w.wsaGetLastError();
          if (err == w.wsaEconnreset) {
            _emitReply(
                emit, seq, dst.address, rtt, 'port unreachable', audible);
            rtts.add(rtt);
            answered = true;
          }
        }
      } finally {
        w.wsaClose(fd);
      }
    });
    if (!answered) emit({'type': 'timeout', 'seq': seq});
    final rest = interval - sw.elapsedMilliseconds;
    if (rest > 0) w.sleepMs(rest);
  }
  _finishPing(emit, sent, rtts, 'finished');
}

// -- route ----------------------------------------------------------------------

/// ICMP traceroute — one batched async send per hop via
/// IcmpSendEcho2/Icmp6SendEchoistry events, then collect until every
/// probe answered or maxDelay elapsed. UDP-probe mode falls back to
/// ICMP (raw sockets need admin on Windows, same as the macOS sandbox).
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

  final hopResults = <int, List<Map<String, Object?>?>>{};
  final nameCache = <String, String>{};
  var reached = false;
  var hopsDone = 0;

  try {
    for (var hop = 1; hop <= maxHops && !reached; hop++) {
      // Fire all probes of this hop back-to-back on event handles.
      final results = using((arena) {
        final events = arena<IntPtr>(pph);
        final replies = arena<Uint8>(pph * 512);
        final opts = arena<w.IP_OPTION_INFORMATION>(pph);
        final out = List<_EchoResult?>.filled(pph, null);
        final replySize = v6
            ? sizeOf<w.ICMPV6_ECHO_REPLY>() + 32 + 8
            : sizeOf<w.ICMP_ECHO_REPLY>() + 24 + 8;
        final payload = v6 ? 32 : 24;
        final dstSa = v6 ? w.sockaddrIn6(arena, dst, scopeId: _scopeIdOf(dst)) : nullptr;
        final srcSa = v6 ? w.sockaddrIn6(arena, InternetAddress('::')) : nullptr;
        var destV4 = 0;
        if (!v6) {
          final a = dst.rawAddress;
          destV4 = a[0] | a[1] << 8 | a[2] << 16 | a[3] << 24;
        }
        var pending = 0;
        var sendErr = 0;
        for (var p = 0; p < pph; p++) {
          events[p] = w.createEvent();
          final opt = opts + p;
          opt.ref
            ..Ttl = hop
            ..Tos = 0
            ..Flags = 0
            ..OptionsSize = 0
            ..OptionsData = nullptr;
          final req = arena<Uint8>(payload);
          for (var i = 0; i < payload; i++) {
            req[i] = i & 0xff;
          }
          final reply = replies + p * 512;
          final r = v6
              ? w.icmp6SendEcho2Async(handle, events[p], srcSa, dstSa, req,
                  payload, opt, reply, replySize, maxDelay)
              : w.icmpSendEcho2(handle, events[p], destV4, req, payload,
                  opt, reply, replySize, maxDelay);
          if (r > 0) {
            // Completed inline — the reply buffer is already valid.
            out[p] = v6 ? _parse6(reply) : _parse4(reply);
          } else if (w.wsaGetLastError() == 997 /* ERROR_IO_PENDING */) {
            pending++;
          } else {
            out[p] = _EchoError(w.wsaGetLastError());
            sendErr = w.wsaGetLastError();
          }
          if (p + 1 < pph && minDelay > 0) w.sleepMs(minDelay);
        }
        if (sendErr != 0) {
          emit({'type': 'note', 'message': 'probe send failed: $sendErr'});
        }

        // Collect until all answered or the deadline passes.
        final deadline =
            DateTime.now().add(Duration(milliseconds: maxDelay));
        while (pending > 0) {
          final remain =
              deadline.difference(DateTime.now()).inMilliseconds;
          if (remain <= 0) break;
          final signaled =
              w.waitForObjects(events, pph, remain.clamp(0, maxDelay));
          if (signaled == 0xFFFFFFFF /* WAIT_FAILED */ ||
              signaled == 0x102 /* WAIT_TIMEOUT */) {
            break;
          }
          for (var p = 0; p < pph; p++) {
            if (out[p] != null) continue;
            final evPtr = arena<IntPtr>(1)..value = events[p];
            if (w.waitForObjects(evPtr, 1, 0) != 0) continue;
            out[p] = v6
                ? _parse6(replies + p * 512)
                : _parse4(replies + p * 512);
            pending--;
          }
        }
        for (final ev in List.generate(pph, (i) => events[i])) {
          w.closeHandle(ev);
        }
        return out;
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
      hopResults[hop] = probes;
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
    'reason': 'finished',
    'hops': hopsDone,
    'reached': reached,
  });
}

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
