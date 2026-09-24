// ignore_for_file: avoid_print
// Smoke-test harness for the Windows FFI backend — exercises every
// `netnatscan/network` method directly (no Flutter binding needed).
// Run: dart run tool/smoke_win32.dart
import 'dart:async';

import 'package:netnatscan/services/win32_backend.dart';
import 'package:netnatscan/services/win32_tools.dart';

Future<void> main() async {
  var failures = 0;
  Future<void> step(String name, FutureOr<Object?> Function() fn) async {
    try {
      final res = await fn();
      print('OK   $name: ${_short(res)}');
    } catch (e, st) {
      failures++;
      print('FAIL $name: $e\n$st');
    }
  }

  await step('getNetworkInfo', () => Win32Backend.invoke('getNetworkInfo'));
  await step('getArpTable', () => Win32Backend.invoke('getArpTable'));
  await step('getNdpTable', () => Win32Backend.invoke('getNdpTable'));
  await step('triggerNdp', () => Win32Backend.invoke('triggerNdp', 'Wi-Fi'));
  await step(
      'getConnectionInfo', () => Win32Backend.invoke('getConnectionInfo'));
  await step(
      'getWifiNetworks', () => Win32Backend.invoke('getWifiNetworks'));

  // Ping: subscribe to the tool event stream, run 2 ICMP echoes at
  // the default gateway (or 127.0.0.1), collect events until done.
  final sub = Win32ToolEngine.instance.events.listen(print);
  final info = await Win32Backend.invoke('getNetworkInfo') as Map?;
  final target = info?['defaultGateway'] as String? ?? '127.0.0.1';
  print('--- ping $target ---');
  await step('startPing', () => Win32Backend.invoke('startPing', {
        'host': target,
        'job': 1,
        'count': 2,
        'intervalMs': 500,
        'payloadBytes': 32,
        'protocol': 'icmp',
      }));
  await Future.delayed(const Duration(seconds: 4));

  print('--- route $target ---');
  await step('startRoute', () => Win32Backend.invoke('startRoute', {
        'host': target,
        'job': 2,
        'maxHops': 4,
        'probesPerHop': 2,
        'maxDelayMs': 1500,
        'minDelayMs': 50,
      }));
  await Future.delayed(const Duration(seconds: 8));
  await step('stopTool', () => Win32Backend.invoke('stopTool'));
  await sub.cancel();

  print(failures == 0 ? 'ALL OK' : '$failures FAILURES');
}

String _short(Object? res) {
  final s = res.toString();
  return s.length > 220 ? '${s.substring(0, 220)}…' : s;
}
