import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

/// Result of a browse: service instances plus per-device hostnames learned
/// from reverse-PTR announcements (`187.0.168.192.in-addr.arpa -> name.local`).
class MdnsResult {
  final List<MdnsService> services;

  /// IPv4 → hostname asserted by the device's own reverse-PTR
  /// (`187.0.168.192.in-addr.arpa -> name.local`) — the strongest hint,
  /// this is the device naming itself.
  final Map<String, String> ptrNames;

  /// IPv4 → hostname resolved from SRV targets via A records — a service
  /// detail that usually equals the device hostname but can be generic
  /// ("Android") or a UUID.
  final Map<String, String> hostNames;

  MdnsResult(this.services, this.ptrNames, this.hostNames);
}

/// A discovered Bonjour/mDNS service instance.
class MdnsService {
  /// Instance label, e.g. "Tamino's iPhone" — the human-facing name devices
  /// with private MACs broadcast and ARP/OUI cannot provide.
  final String name;

  /// Service type without the domain, e.g. `_companion-link._tcp`.
  final String type;

  /// SRV target hostname, e.g. `taminos-iphone.local`.
  String? host;
  int? port;
  final Set<String> ips = {};

  /// IPs proven by the SRV target's A/AAAA records — the set that actually
  /// owns this service. `ips` also includes mere PTR senders, which can
  /// mirror other devices' services.
  final Set<String> resolvedIps = {};
  final Map<String, String> txt = {};

  MdnsService(this.name, this.type);
}

/// Discovers Bonjour services by speaking mDNS directly: multicast DNS
/// queries to 224.0.0.251:5353 over a plain UDP socket.
///
/// This deliberately bypasses NetServiceBrowser/mDNSResponder — on macOS
/// 15+ the daemon's trust check rejects browses unless the app satisfies
/// Local Network privacy requirements, which sandboxed debug builds can't
/// reliably meet. Raw multicast UDP needs only the network.client sandbox
/// entitlement.
class MdnsDiscovery {
  static final _group = InternetAddress('224.0.0.251');
  static const _port = 5353;

  /// Queries the LAN for [types] (e.g. `_companion-link._tcp`) plus the
  /// `_services._dns-sd._udp` enumeration, then makes a second pass over any
  /// service types discovered that weren't asked for.
  static Future<MdnsResult> browse({
    required List<String> types,
    Duration timeout = const Duration(milliseconds: 3500),
    List<String> targets = const [],
  }) async {
    // Two sockets:
    // - tx on an ephemeral port sends QU-bit queries to the multicast group
    //   and to each ARP-discovered device directly. Responders answer via
    //   unicast to the source port — always reaching us.
    // - rx on 5353 joined to the multicast group catches multicast replies
    //   and ambient announcements (SO_REUSEPORT shares the port with
    //   mDNSResponder; multicast is replicated to every joined socket).
    final tx = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    RawDatagramSocket? rx;
    try {
      rx = await RawDatagramSocket.bind(
        InternetAddress.anyIPv4,
        _port,
        reuseAddress: true,
        // SO_REUSEPORT doesn't exist on Windows — SO_REUSEADDR alone
        // is enough to share the mDNS port there.
        reusePort: !Platform.isWindows,
      );
      try {
        final ifaces = await NetworkInterface.list(
          type: InternetAddressType.IPv4,
          includeLoopback: false,
        );
        for (final i in ifaces) {
          try {
            rx.joinMulticast(_group, i);
          } catch (_) {}
        }
      } catch (_) {}
      try {
        rx.joinMulticast(_group);
      } catch (_) {}
    } catch (_) {
      rx = null;
    }

    final services = <String, MdnsService>{};
    final hostIps = <String, Set<String>>{};
    final ptrNames = <String, String>{};
    final hostNames = <String, String>{};
    final seenTypes = <String>{};
    final queued = <String>{
      for (final t in types) _fqdn(t),
      '_services._dns-sd._udp.local',
    };
    seenTypes.addAll(queued.map((t) => t.toLowerCase()));

    void onPacket(RawDatagramSocket s) {
      final dg = s.receive();
      if (dg == null) return;
      _parseMessage(
        dg.data,
        dg.address.address,
        services,
        hostIps,
        (typeFqdn) {
          final key = typeFqdn.toLowerCase();
          if (seenTypes.add(key) && queued.length < 64) {
            queued.add(typeFqdn);
          }
        },
        (ip, name) => ptrNames.putIfAbsent(ip, () => name),
      );
    }

    final listeners = [
      tx.listen((e) {
        if (e == RawSocketEvent.read) onPacket(tx);
      }),
      if (rx != null)
        rx.listen((e) {
          if (e == RawSocketEvent.read) onPacket(rx!);
        }),
    ];

    final unicastTargets = [
      for (final t in targets) InternetAddress.tryParse(t),
    ].nonNulls.toList();

    void sendQuery() {
      final batch = queued.toList();
      queued.clear();
      if (batch.isEmpty) return;
      final q = _buildQuery(batch);
      tx.send(q, _group, _port);
      for (final t in unicastTargets) {
        tx.send(q, t, _port);
      }
    }

    sendQuery();
    await Future.delayed(timeout ~/ 3);
    sendQuery(); // retransmit + newly enumerated types
    await Future.delayed(timeout ~/ 3);
    sendQuery(); // late enumeration stragglers
    await Future.delayed(timeout - timeout ~/ 3 - timeout ~/ 3);

    for (final l in listeners) {
      await l.cancel();
    }
    rx?.close();
    tx.close();

    // Resolve SRV targets to addresses collected anywhere in the trace.
    // Names are only attributed through real A/AAAA records — devices can
    // echo each other's services (iOS mirrors companion-link), so the
    // packet source is not a reliable name hint.
    for (final s in services.values) {
      final h = s.host;
      if (h == null) continue;
      final ips = hostIps[h.toLowerCase()] ?? const <String>{};
      s.ips.addAll(ips);
      s.resolvedIps.addAll(ips);
      for (final ip in ips) {
        hostNames.putIfAbsent(ip, () => _stripLocal(h));
      }
    }
    return MdnsResult(services.values.toList(), ptrNames, hostNames);
  }

  static String _fqdn(String type) =>
      type.endsWith('.local') ? type : '$type.local';

  // --- packet construction ---

  static Uint8List _buildQuery(List<String> names) {
    final b = BytesBuilder();
    b.add([0, 0, 0, 0, (names.length >> 8) & 0xFF, names.length & 0xFF]);
    b.add([0, 0, 0, 0, 0, 0]); // no answer/authority/additional records
    for (final n in names) {
      _writeName(b, n);
      // QU bit: responders answer via unicast to our ephemeral tx port.
      b.add([0, 12, 0x80, 1]); // PTR, class IN + unicast-response bit
    }
    return b.toBytes();
  }

  static void _writeName(BytesBuilder b, String name) {
    for (final label in name.split('.')) {
      if (label.isEmpty) continue;
      final bytes = utf8.encode(label);
      b.addByte(bytes.length);
      b.add(bytes);
    }
    b.addByte(0);
  }

  // --- packet parsing ---

  static void _parseMessage(
    Uint8List d,
    String sourceIp,
    Map<String, MdnsService> services,
    Map<String, Set<String>> hostIps,
    void Function(String typeFqdn) onType,
    void Function(String ip, String name) onDeviceName,
  ) {
    if (d.length < 12) return;
    final qd = (d[4] << 8) | d[5];
    final an = (d[6] << 8) | d[7];
    final ns = (d[8] << 8) | d[9];
    final ar = (d[10] << 8) | d[11];

    var pos = 12;
    for (var i = 0; i < qd; i++) {
      final (_, end) = _readName(d, pos);
      pos = end + 4;
      if (pos > d.length) return;
    }

    final records = <_RR>[];
    for (var i = 0; i < an + ns + ar && pos < d.length; i++) {
      final (name, end) = _readName(d, pos);
      pos = end;
      if (pos + 10 > d.length) return;
      final type = (d[pos] << 8) | d[pos + 1];
      final rdlen = (d[pos + 8] << 8) | d[pos + 9];
      final rdata = pos + 10;
      if (rdata + rdlen > d.length) return;
      records.add(_RR(name, type, rdata, rdlen));
      pos = rdata + rdlen;
    }

    for (final rr in records) {
      switch (rr.type) {
        case 12: // PTR
          final (target, _) = _readName(d, rr.rdata);
          final owner = rr.name.toLowerCase();
          if (owner == '_services._dns-sd._udp.local') {
            onType(target); // type enumeration answer
          } else if (owner.endsWith('.in-addr.arpa')) {
            // Reverse announcement: ip -> the device's pretty hostname.
            final ip = _ipv4FromArpa(owner);
            if (ip != null) onDeviceName(ip, _stripLocal(target));
          } else if (!owner.contains('._sub.')) {
            _serviceFor(services, target, rr.name)?.ips.add(sourceIp);
          }
        case 33: // SRV
          if (rr.rdlen >= 8) {
            final (target, _) = _readName(d, rr.rdata + 6);
            final svc = _lookup(services, rr.name);
            svc?.port = (d[rr.rdata + 4] << 8) | d[rr.rdata + 5];
            svc?.host = target;
          }
        case 16: // TXT
          final svc = _lookup(services, rr.name);
          var p = rr.rdata;
          final end = rr.rdata + rr.rdlen;
          while (p < end) {
            final len = d[p++];
            if (p + len > end) break;
            final kv = utf8.decode(d.sublist(p, p + len), allowMalformed: true);
            final eq = kv.indexOf('=');
            if (svc != null && eq > 0) {
              svc.txt[kv.substring(0, eq)] = kv.substring(eq + 1);
            }
            p += len;
          }
        case 1: // A
          if (rr.rdlen == 4) {
            hostIps
                .putIfAbsent(rr.name.toLowerCase(), () => {})
                .add(d.sublist(rr.rdata, rr.rdata + 4).join('.'));
          }
        case 28: // AAAA
          if (rr.rdlen == 16) {
            final parts = List.generate(
              8,
              (i) => ((d[rr.rdata + i * 2] << 8) | d[rr.rdata + i * 2 + 1])
                  .toRadixString(16),
            );
            hostIps
                .putIfAbsent(rr.name.toLowerCase(), () => {})
                .add(parts.join(':'));
          }
      }
    }
  }

  /// Registers a service instance for PTR target `instanceFqdn`
  /// (e.g. `Tamino's iPhone._companion-link._tcp.local`) advertised by owner
  /// `typeFqdn` (`_companion-link._tcp.local`).
  static MdnsService? _serviceFor(
    Map<String, MdnsService> services,
    String instanceFqdn,
    String typeFqdn,
  ) {
    // A real instance name ends with the type's FQDN and isn't itself a
    // `_type` label — filters subtype/reverse-PTR noise.
    if (!instanceFqdn.toLowerCase().endsWith(typeFqdn.toLowerCase())) {
      return null;
    }
    final labels = _labels(instanceFqdn);
    if (labels.length < 2 || labels.first.startsWith('_')) return null;
    final typeLabels = _labels(typeFqdn);
    final type = typeLabels
        .take(typeLabels.length - 1)
        .join('.'); // strip "local"
    final svc = services.putIfAbsent(
      instanceFqdn.toLowerCase(),
      () => MdnsService(labels.first, type),
    );
    return svc;
  }

  /// `187.0.168.192.in-addr.arpa` -> `192.168.0.187`.
  static String? _ipv4FromArpa(String owner) {
    final labels = owner.split('.');
    if (labels.length < 6) return null;
    final octets = labels.take(4).toList().reversed.toList();
    if (octets.any((o) => int.tryParse(o) == null || int.parse(o) > 255)) {
      return null;
    }
    return octets.join('.');
  }

  /// `name.local` -> `name`, preserving case.
  static String _stripLocal(String name) =>
      name.toLowerCase().endsWith('.local')
      ? name.substring(0, name.length - 6)
      : name;

  /// Looks up a service by its full instance FQDN (SRV/TXT owner name).
  static MdnsService? _lookup(Map<String, MdnsService> services, String name) =>
      services[name.toLowerCase()];

  static List<String> _labels(String name) =>
      name.split('.').where((l) => l.isNotEmpty).toList();

  /// Reads a (possibly compressed) domain name at [off].
  /// Returns the decoded name and the offset just past it in the message.
  static (String, int) _readName(Uint8List d, int off) {
    final labels = <String>[];
    var pos = off;
    var end = -1;
    var hops = 0;
    while (pos < d.length) {
      final len = d[pos];
      if (len == 0) {
        if (end < 0) end = pos + 1;
        pos++;
        break;
      }
      if ((len & 0xC0) == 0xC0) {
        if (pos + 1 >= d.length) break;
        final ptr = ((len & 0x3F) << 8) | d[pos + 1];
        if (end < 0) end = pos + 2;
        pos = ptr;
        if (++hops > 40) break;
        continue;
      }
      pos++;
      if (pos + len > d.length) break;
      labels.add(utf8.decode(d.sublist(pos, pos + len), allowMalformed: true));
      pos += len;
    }
    return (labels.join('.'), end < 0 ? pos : end);
  }
}

class _RR {
  final String name;
  final int type;
  final int rdata;
  final int rdlen;
  _RR(this.name, this.type, this.rdata, this.rdlen);
}
