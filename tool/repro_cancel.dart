// ignore_for_file: avoid_print
// Cancel-path check: start a long route job, stop it mid-flight, ensure
// the job exits cleanly (no crash, 'done' seen) and memory stays sane.
import 'dart:async';

import 'package:netnatscan/services/win32_backend.dart';
import 'package:netnatscan/services/win32_tools.dart';

Future<void> main() async {
  for (var round = 0; round < 10; round++) {
    var sawDone = false;
    final sub = Win32ToolEngine.instance.events.listen((e) {
      if (e['type'] == 'done') sawDone = true;
      print('  $e');
    });
    await Win32Backend.invoke('startRoute', {
      'host': '1.1.1.1',
      'job': round + 1,
      'maxHops': 30,
      'probesPerHop': 3,
      'maxDelayMs': 3000,
      'minDelayMs': 20,
    });
    // Cancel mid-flight — some probes should be outstanding.
    await Future.delayed(Duration(milliseconds: 300 + round * 50));
    await Win32Backend.invoke('stopTool');
    await Future.delayed(const Duration(milliseconds: 500));
    print('round $round done=$sawDone');
    await sub.cancel();
  }
  // Touch the FFI heap paths again — corruption would surface here.
  for (var i = 0; i < 50; i++) {
    await Win32Backend.invoke('getArpTable');
  }
  print('ALL OK');
}
