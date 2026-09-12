import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// What one device volunteered via SSDP/UPnP: the M-SEARCH response
/// headers plus its device-description XML (friendlyName, manufacturer,
/// model) fetched from LOCATION — the strongest non-Bonjour identity on
/// TVs, cameras, routers and IoT gear.
class SsdpDevice {
  final String ip;
  String? server;
  String? location;
  String? usn;
  final Set<String> sts = {};

  // From the description document.
  String? friendlyName;
  String? manufacturer;
  String? modelName;
  String? modelNumber;
  String? deviceType;
  String? udn;
  String? serialNumber;
  String? presentationUrl;

  SsdpDevice(this.ip);
}

/// Speaks UPnP SSDP directly: `M-SEARCH *` to 239.255.255.250:1900 plus
/// unicast copies at each ARP target (replies come back unicast to our
/// ephemeral port). Then a small HTTP fetch of each device's LOCATION
/// URL yields its self-description.
class SsdpDiscovery {
  static final _group = InternetAddress('239.255.255.250');
  static const _port = 1900;

  static final _query = utf8.encode(
    'M-SEARCH * HTTP/1.1\r\n'
    'HOST: 239.255.255.250:1900\r\n'
    'MAN: "ssdp:discover"\r\n'
    'MX: 1\r\n'
    'ST: ssdp:all\r\n'
    '\r\n',
  );

  /// Returns the answering devices keyed by IPv4. [timeout] bounds the
  /// multicast collection; description fetches add up to ~2s more.
  static Future<Map<String, SsdpDevice>> discover({
    Duration timeout = const Duration(milliseconds: 2500),
    List<String> targets = const [],
  }) async {
    final sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    final devices = <String, SsdpDevice>{};
    final sub = sock.listen((event) {
      if (event != RawSocketEvent.read) return;
      final dg = sock.receive();
      if (dg == null) return;
      _parse(dg, devices);
    });

    try {
      // Repeat — power-saving devices miss individual datagrams.
      for (var i = 0; i < 3; i++) {
        sock.send(_query, _group, _port);
        for (final t in targets) {
          try {
            sock.send(_query, InternetAddress(t), _port);
          } catch (_) {}
        }
        if (i < 2) await Future.delayed(const Duration(milliseconds: 400));
      }
      await Future.delayed(timeout);
    } finally {
      await sub.cancel();
      sock.close();
    }

    // Fetch each device's description document — that's where the
    // friendly name and manufacturer live.
    final pending = <Future<void>>[];
    for (final d in devices.values) {
      if (d.location != null) pending.add(_fetchDescription(d));
    }
    await _pool(pending, 8);
    return devices;
  }

  static void _parse(Datagram dg, Map<String, SsdpDevice> devices) {
    final ip = dg.address.address;
    String text;
    try {
      text = ascii.decode(dg.data, allowInvalid: true);
    } catch (_) {
      return;
    }
    if (!text.startsWith('HTTP/1.1 200') && !text.startsWith('HTTP/1.0 200')) {
      return;
    }
    final d = devices.putIfAbsent(ip, () => SsdpDevice(ip));
    for (final line in text.split('\r\n')) {
      final i = line.indexOf(':');
      if (i <= 0) continue;
      final key = line.substring(0, i).trim().toLowerCase();
      final value = line.substring(i + 1).trim();
      switch (key) {
        case 'server':
          d.server = value;
        case 'location':
          d.location = value;
        case 'st':
          d.sts.add(value);
        case 'usn':
          d.usn ??= value;
          // USN embeds the device URN for root devices.
          if (value.contains('::urn:')) {
            d.sts.add(value.substring(value.indexOf('::') + 2));
          }
      }
    }
  }

  static Future<void> _fetchDescription(SsdpDevice d) async {
    final uri = Uri.tryParse(d.location!);
    if (uri == null) return;
    final client = HttpClient();
    client.connectionTimeout = const Duration(milliseconds: 1200);
    try {
      final req = await client
          .getUrl(uri)
          .timeout(const Duration(milliseconds: 1500));
      final resp = await req.close().timeout(
        const Duration(milliseconds: 1500),
      );
      if (resp.statusCode != 200) return;
      final body = await resp
          .transform(utf8.decoder)
          .join()
          .timeout(const Duration(milliseconds: 1500));
      d.friendlyName = _tag(body, 'friendlyName');
      d.manufacturer = _tag(body, 'manufacturer');
      d.modelName = _tag(body, 'modelName');
      d.modelNumber = _tag(body, 'modelNumber');
      d.deviceType = _tag(body, 'deviceType');
      d.udn = _tag(body, 'UDN');
      d.serialNumber = _tag(body, 'serialNumber');
      d.presentationUrl = _tag(body, 'presentationURL');
    } catch (_) {
    } finally {
      client.close();
    }
  }

  /// First `<tag>…</tag>` contents — device-description fields are flat
  /// enough that a regex beats pulling in an XML dependency.
  static String? _tag(String xml, String tag) {
    final m = RegExp(
      '<$tag[^>]*>([^<]*)</$tag>',
      caseSensitive: false,
    ).firstMatch(xml);
    final v = m?.group(1)?.trim();
    return (v == null || v.isEmpty) ? null : v;
  }

  static Future<void> _pool(List<Future<void>> futures, int limit) async {
    for (var i = 0; i < futures.length; i += limit) {
      await Future.wait(futures.skip(i).take(limit));
    }
  }
}
