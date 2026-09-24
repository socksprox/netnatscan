/// Single dispatch point for the `netnatscan/network` surface.
///
/// On macOS the backend is `NetworkPlugin.swift` behind a real
/// MethodChannel/EventChannel pair. On Windows there is no plugin —
/// the same methods are answered in-process by [Win32Backend] via
/// dart:ffi and tool events come from [Win32ToolEngine]'s broadcast
/// stream. Widget tests always take the channel path so their
/// `setMockMethodCallHandler` mocks keep intercepting on any host.
library;

import 'dart:io';

import 'package:flutter/services.dart';

import 'win32_backend.dart';
import 'win32_tools.dart';

class NetChannel {
  static const _methods = MethodChannel('netnatscan/network');
  static const _events = EventChannel('netnatscan/tools_events');

  static bool get _windowsBackend =>
      Platform.isWindows &&
      Platform.environment['FLUTTER_TEST'] != 'true';

  /// Raw invoke — mirrors MethodChannel.invokeMethod.
  static Future<dynamic> invoke(String method, [Object? arguments]) {
    if (_windowsBackend) {
      return Win32Backend.invoke(method, arguments);
    }
    return _methods.invokeMethod(method, arguments);
  }

  /// Mirrors `MethodChannel.invokeMapMethod<String, dynamic>`.
  static Future<Map<String, dynamic>?> invokeMap(String method,
      [Object? arguments]) async {
    if (_windowsBackend) {
      final res = await Win32Backend.invoke(method, arguments);
      return (res as Map?)?.cast<String, dynamic>();
    }
    return _methods.invokeMapMethod<String, dynamic>(method, arguments);
  }

  /// Mirrors `MethodChannel.invokeListMethod<Map<dynamic, dynamic>>`.
  static Future<List<Map<dynamic, dynamic>>?> invokeList(String method,
      [Object? arguments]) async {
    if (_windowsBackend) {
      final res = await Win32Backend.invoke(method, arguments);
      return (res as List?)?.cast<Map<dynamic, dynamic>>();
    }
    return _methods.invokeListMethod<Map<dynamic, dynamic>>(
        method, arguments);
  }

  /// Mirrors EventChannel.receiveBroadcastStream on
  /// `netnatscan/tools_events`.
  static Stream<dynamic> get toolsEvents => _windowsBackend
      ? Win32ToolEngine.instance.events
      : _events.receiveBroadcastStream();
}
