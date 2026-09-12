import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

/// One NetBIOS name from a node-status answer: the 15-char name, its
/// suffix byte (0x00 workstation, 0x20 file server, 0x1B domain master
/// browser, 0x1C domain controllers) and whether it is unique (a
/// machine name) or a group (workgroup/domain).
class NbnsName {
  final String name;
  final int suffix;
  final bool unique;

  NbnsName(this.name, this.suffix, this.unique);

  /// `<00>`-style suffix label, like nbtstat prints it.
  String get label =>
      '$name <${suffix.toRadixString(16).toUpperCase().padLeft(2, '0')}>';
}

/// Asks a device for its NetBIOS name table via one unicast UDP/137
/// wildcard NBSTAT query — the way Windows hosts, Samba NASes and many
/// printers/NAS devices still identify themselves.
class NbnsDiscovery {
  static const _port = 137;

  /// Node-status request for '*' — the wildcard name encodes to "CK"
  /// followed by 30 'A's (16-byte name: 0x2A then fifteen NULs, each
  /// nibble mapped to 'A'..'P').
  static Uint8List _buildQuery() {
    final q = BytesBuilder();
    q.add([0x12, 0x34]); // transaction id
    q.add([0x00, 0x00]); // flags: query
    q.add([0x00, 0x01]); // qdcount
    q.add([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // an/ns/ar
    q.addByte(0x20); // encoded name length
    q.add(('CK${'A' * 30}').codeUnits);
    q.addByte(0x00); // name terminator
    q.add([0x00, 0x21]); // NBSTAT
    q.add([0x00, 0x01]); // IN
    return q.toBytes();
  }

  /// Returns the device's registered names, or empty if silent/filtered.
  static Future<List<NbnsName>> query(
    String ip, {
    Duration timeout = const Duration(milliseconds: 700),
  }) async {
    RawDatagramSocket? sock;
    try {
      sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      final done = Completer<Datagram?>();
      late StreamSubscription<RawSocketEvent> sub;
      sub = sock.listen((event) {
        if (event != RawSocketEvent.read) return;
        final dg = sock!.receive();
        if (dg != null && dg.address.address == ip && !done.isCompleted) {
          done.complete(dg);
        }
      });
      sock.send(_buildQuery(), InternetAddress(ip), _port);
      final dg = await done.future.timeout(timeout, onTimeout: () => null);
      await sub.cancel();
      if (dg == null) return const [];
      return _parse(dg.data);
    } catch (_) {
      return const [];
    } finally {
      sock?.close();
    }
  }

  static List<NbnsName> _parse(Uint8List data) {
    if (data.length < 12) return const [];
    final anCount = (data[6] << 8) | data[7];
    if (anCount == 0) return const [];
    var off = _skipName(data, 12); // echoed question name
    off += 4; // qtype + qclass
    final names = <NbnsName>[];
    for (var rr = 0; rr < anCount && off + 12 <= data.length; rr++) {
      off = _skipName(data, off); // answer name: pointer or literal
      final type = (data[off] << 8) | data[off + 1];
      off += 8; // type + class + ttl
      final rdLength = (data[off] << 8) | data[off + 1];
      off += 2;
      if (off + rdLength > data.length) break;
      if (type != 0x0021 || rdLength < 7) {
        off += rdLength;
        continue;
      }
      // Name table: count(1) + 18B entries + 6B adapter stats.
      final count = data[off];
      var p = off + 1;
      for (var i = 0; i < count && p + 18 <= off + rdLength; i++) {
        final name = String.fromCharCodes(data.sublist(p, p + 15)).trimRight();
        final suffix = data[p + 15];
        final flags = (data[p + 16] << 8) | data[p + 17];
        if (name.isNotEmpty) {
          names.add(NbnsName(name, suffix, flags & 0x8000 == 0));
        }
        p += 18;
      }
      off += rdLength;
    }
    return names;
  }

  /// A DNS-style name is either a 2-byte compression pointer (0xC0xx)
  /// or a literal length-prefixed string ending in a zero byte.
  static int _skipName(Uint8List data, int off) {
    while (off < data.length) {
      final len = data[off];
      if (len & 0xC0 == 0xC0) return off + 2;
      if (len == 0) return off + 1;
      off += len + 1;
    }
    return data.length;
  }
}
