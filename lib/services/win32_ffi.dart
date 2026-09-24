/// FFI bindings for the parts of the Windows networking surface that
/// package:win32 doesn't wrap: the neighbour table (GetIpNetTable2),
/// interface counters (GetIfTable2), best-route lookup (GetBestRoute2),
/// the ICMP echo helpers (IcmpSendEcho / Icmp6SendEcho2) and the ws2_32
/// calls needed for the NDP trigger and UDP ping.
///
/// Everything is `late`/lazy so importing this file on other platforms
/// is harmless — the DLLs are only opened when a symbol is first used.
library;

// Struct field names mirror the C API; padding fields exist for layout.
// ignore_for_file: camel_case_types, non_constant_identifier_names, unused_field

import 'dart:ffi';
import 'dart:io' show InternetAddress;

import 'package:ffi/ffi.dart';
import 'package:win32/win32.dart' show GUID;

// -- Address families / socket constants -------------------------------------

const afInet = 2;
const afInet6 = 23;
const sockDgram = 2;
const ipprotoUdp = 17;
const solSocket = 0xffff;
const soRcvtimeo = 0x1006;

// ICMP status codes (ipexport.h).
const ipSuccess = 0;
const ipReqTimedOut = 11010;
const ipTtlExpiredTransit = 11013;
const ipFlagDf = 0x02;

// Winsock error codes.
const wsaEconnreset = 10054;
const wsaEtimedout = 10060;

// -- Structs ------------------------------------------------------------------

final class SOCKADDR_IN6 extends Struct {
  @Uint16()
  external int sin6_family;
  @Uint16()
  external int sin6_port;
  @Uint32()
  external int sin6_flowinfo;
  @Array(16)
  external Array<Uint8> sin6_addr;
  @Uint32()
  external int sin6_scope_id;
}

/// SOCKADDR_INET: union { ADDRESS_FAMILY si_family; SOCKADDR_IN Ipv4;
/// SOCKADDR_IN6 Ipv6; } — 28 bytes, 4-aligned.
final class SOCKADDR_INET extends Union {
  external SOCKADDR_IN6 Ipv6;
  @Uint16()
  external int si_family;
}

/// MIB_IPNET_ROW2 (netioapi.h) — one neighbour-cache row.
final class MIB_IPNET_ROW2 extends Struct {
  external SOCKADDR_INET Address; // 0..28
  @Uint32()
  external int InterfaceIndex; // 28
  @Uint64()
  external int InterfaceLuid; // 32
  @Array(32)
  external Array<Uint8> PhysicalAddress; // 40
  @Uint32()
  external int PhysicalAddressLength; // 72
  @Int32()
  external int State; // 76 — NL_NEIGHBOR_STATE
  @Uint8()
  external int Flags; // 80 — IsRouter/IsUnreachable bitfield union
  @Uint8()
  external int _pad0;
  @Uint8()
  external int _pad1;
  @Uint8()
  external int _pad2;
  @Uint32()
  external int ReachabilityTime; // 84 — union { LastReachable/LastUnreachable }
  @Uint32()
  external int _pad3; // 88 — tail pad to 96
}

/// Header of MIB_IPNET_TABLE2 — rows follow at offset 8.
final class MIB_IPNET_TABLE2 extends Struct {
  @Uint32()
  external int NumEntries;
}

final class IP_PREFIX extends Struct {
  external SOCKADDR_INET Prefix;
  @Uint8()
  external int PrefixLength;
}

/// MIB_IPFORWARD_ROW2 — filled by GetBestRoute2.
final class MIB_IPFORWARD_ROW2 extends Struct {
  @Uint64()
  external int InterfaceLuid; // 0
  @Uint32()
  external int InterfaceIndex; // 8
  external IP_PREFIX DestinationPrefix; // 12..44
  external SOCKADDR_INET NextHop; // 44..72
  @Uint8()
  external int SitePrefixLength; // 72
  @Uint8()
  external int _p0;
  @Uint8()
  external int _p1;
  @Uint8()
  external int _p2;
  @Uint32()
  external int ValidLifetime; // 76
  @Uint32()
  external int PreferredLifetime; // 80
  @Uint32()
  external int Metric; // 84
  @Int32()
  external int Protocol; // 88
  @Uint8()
  external int Loopback; // 92
  @Uint8()
  external int AutoconfigureAddress;
  @Uint8()
  external int Publish;
  @Uint8()
  external int Immortal;
  @Uint32()
  external int Age; // 96
  @Int32()
  external int Origin; // 100 → sizeof 104
}

/// MIB_IF_ROW2 (netioapi.h) — per-interface counters + identity.
final class MIB_IF_ROW2 extends Struct {
  @Uint64()
  external int InterfaceLuid;
  @Uint32()
  external int InterfaceIndex;
  external GUID InterfaceGuid;
  @Array(257)
  external Array<Uint16> Alias;
  @Array(257)
  external Array<Uint16> Description;
  @Uint32()
  external int PhysicalAddressLength;
  @Array(32)
  external Array<Uint8> PhysicalAddress;
  @Array(32)
  external Array<Uint8> PermanentPhysicalAddress;
  @Uint32()
  external int Mtu;
  @Uint32()
  external int Type;
  @Int32()
  external int TunnelType;
  @Int32()
  external int MediaType;
  @Int32()
  external int AccessType;
  @Int32()
  external int DirectionType;
  @Uint8()
  external int InterfaceAndOperStatusFlags;
  @Uint8()
  external int _f0;
  @Uint8()
  external int _f1;
  @Uint8()
  external int _f2;
  @Int32()
  external int OperStatus;
  @Int32()
  external int AdminStatus;
  @Int32()
  external int MediaConnectState;
  external GUID NetworkGuid;
  @Int32()
  external int ConnectionType;
  @Uint64()
  external int TransmitLinkSpeed;
  @Uint64()
  external int ReceiveLinkSpeed;
  @Uint64()
  external int InOctets;
  @Uint64()
  external int InUcastPkts;
  @Uint64()
  external int InNUcastPkts;
  @Uint64()
  external int InDiscards;
  @Uint64()
  external int InErrors;
  @Uint64()
  external int InUnknownProtos;
  @Uint64()
  external int InUcastOctets;
  @Uint64()
  external int InMulticastOctets;
  @Uint64()
  external int InBroadcastOctets;
  @Uint64()
  external int OutOctets;
  @Uint64()
  external int OutUcastPkts;
  @Uint64()
  external int OutNUcastPkts;
  @Uint64()
  external int OutDiscards;
  @Uint64()
  external int OutErrors;
  @Uint64()
  external int OutUcastOctets;
  @Uint64()
  external int OutMulticastOctets;
  @Uint64()
  external int OutBroadcastOctets;
  @Uint64()
  external int InQLen;
  @Uint64()
  external int OutQLen;
}

final class MIB_IF_TABLE2 extends Struct {
  @Uint32()
  external int NumEntries;
}

final class IP_OPTION_INFORMATION extends Struct {
  @Uint8()
  external int Ttl;
  @Uint8()
  external int Tos;
  @Uint8()
  external int Flags;
  @Uint8()
  external int OptionsSize;
  external Pointer<Uint8> OptionsData;
}

final class ICMP_ECHO_REPLY extends Struct {
  @Uint32()
  external int Address;
  @Uint32()
  external int Status;
  @Uint32()
  external int RoundTripTime;
  @Uint16()
  external int DataSize;
  @Uint16()
  external int Reserved;
  external Pointer<Uint8> Data;
  external IP_OPTION_INFORMATION Options;
}

/// ICMPV6_ECHO_REPLY: IPV6_ADDRESS_EX {addr[16], scopeId} + Status + RTT.
final class ICMPV6_ECHO_REPLY extends Struct {
  @Array(16)
  external Array<Uint8> Address;
  @Uint32()
  external int ScopeId;
  @Uint32()
  external int Status;
  @Uint32()
  external int RoundTripTime;
}

// -- DLL handles --------------------------------------------------------------
// Top-level finals in Dart initialize lazily, so these libraries are only
// opened when a symbol is first touched — i.e. only on Windows.

final _iphlpapi = DynamicLibrary.open('iphlpapi.dll');
final _kernel32 = DynamicLibrary.open('kernel32.dll');
final _ws2_32 = DynamicLibrary.open('ws2_32.dll');

// -- iphlpapi -----------------------------------------------------------------

final _getIpNetTable2 = _iphlpapi.lookupFunction<
    Uint32 Function(Uint16, Pointer<Pointer>),
    int Function(int, Pointer<Pointer>)>('GetIpNetTable2');

final _freeMibTable = _iphlpapi.lookupFunction<Void Function(Pointer),
    void Function(Pointer)>('FreeMibTable');

final _getIfTable2 = _iphlpapi.lookupFunction<Uint32 Function(Pointer<Pointer>),
    int Function(Pointer<Pointer>)>('GetIfTable2');

final _getBestRoute2 = _iphlpapi.lookupFunction<
    Uint32 Function(Pointer, Uint32, Pointer, Pointer<SOCKADDR_INET>, Uint32,
        Pointer<MIB_IPFORWARD_ROW2>, Pointer<SOCKADDR_INET>),
    int Function(Pointer, int, Pointer, Pointer<SOCKADDR_INET>, int,
        Pointer<MIB_IPFORWARD_ROW2>, Pointer<SOCKADDR_INET>)>('GetBestRoute2');

final _icmpCreateFile =
    _iphlpapi.lookupFunction<IntPtr Function(), int Function()>(
        'IcmpCreateFile');
final _icmp6CreateFile =
    _iphlpapi.lookupFunction<IntPtr Function(), int Function()>(
        'Icmp6CreateFile');
final _icmpCloseHandle =
    _iphlpapi.lookupFunction<Int32 Function(IntPtr), int Function(int)>(
        'IcmpCloseHandle');

final _icmpSendEcho = _iphlpapi.lookupFunction<
    Uint32 Function(IntPtr, Uint32, Pointer, Uint16,
        Pointer<IP_OPTION_INFORMATION>, Pointer, Uint32, Uint32),
    int Function(int, int, Pointer, int, Pointer<IP_OPTION_INFORMATION>,
        Pointer, int, int)>('IcmpSendEcho');

final _icmpSendEcho2 = _iphlpapi.lookupFunction<
    Uint32 Function(IntPtr, IntPtr, Pointer, Pointer, Uint32, Pointer, Uint16,
        Pointer<IP_OPTION_INFORMATION>, Pointer, Uint32, Uint32),
    int Function(int, int, Pointer, Pointer, int, Pointer, int,
        Pointer<IP_OPTION_INFORMATION>, Pointer, int, int)>('IcmpSendEcho2');

final _icmp6SendEcho2 = _iphlpapi.lookupFunction<
    Uint32 Function(IntPtr, IntPtr, Pointer, Pointer, Pointer<SOCKADDR_IN6>,
        Pointer<SOCKADDR_IN6>, Pointer, Uint16, Pointer<IP_OPTION_INFORMATION>,
        Pointer, Uint32, Uint32),
    int Function(int, int, Pointer, Pointer, Pointer<SOCKADDR_IN6>,
        Pointer<SOCKADDR_IN6>, Pointer, int, Pointer<IP_OPTION_INFORMATION>,
        Pointer, int, int)>('Icmp6SendEcho2');

final _getTickCount64 = _kernel32
    .lookupFunction<Uint64 Function(), int Function()>('GetTickCount64');

final _createEventW = _kernel32.lookupFunction<
    IntPtr Function(Pointer, Int32, Int32, Pointer),
    int Function(Pointer, int, int, Pointer)>('CreateEventW');

final _waitForMultipleObjects = _kernel32.lookupFunction<
    Uint32 Function(Uint32, Pointer<IntPtr>, Int32, Uint32),
    int Function(int, Pointer<IntPtr>, int, int)>('WaitForMultipleObjects');

final _closeHandle = _kernel32
    .lookupFunction<Int32 Function(IntPtr), int Function(int)>('CloseHandle');

final _sleep = _kernel32
    .lookupFunction<Void Function(Uint32), void Function(int)>('Sleep');

final _user32 = DynamicLibrary.open('user32.dll');
final _messageBeep = _user32
    .lookupFunction<Int32 Function(Uint32), int Function(int)>(
        'MessageBeep');

// -- ws2_32 -------------------------------------------------------------------

final _wsaSocket = _ws2_32.lookupFunction<IntPtr Function(Int32, Int32, Int32),
    int Function(int, int, int)>('socket');
final _wsaSendto = _ws2_32.lookupFunction<
    Int32 Function(IntPtr, Pointer, Int32, Int32, Pointer, Int32),
    int Function(int, Pointer, int, int, Pointer, int)>('sendto');
final _wsaSend = _ws2_32.lookupFunction<
    Int32 Function(IntPtr, Pointer, Int32, Int32),
    int Function(int, Pointer, int, int)>('send');
final _wsaRecv = _ws2_32.lookupFunction<Int32 Function(IntPtr, Pointer, Int32,
    Int32), int Function(int, Pointer, int, int)>('recv');
final _wsaConnect = _ws2_32.lookupFunction<Int32 Function(IntPtr, Pointer, Int32),
    int Function(int, Pointer, int)>('connect');
final _wsaSetsockopt = _ws2_32.lookupFunction<
    Int32 Function(IntPtr, Int32, Int32, Pointer, Int32),
    int Function(int, int, int, Pointer, int)>('setsockopt');
final _wsaClosesocket = _ws2_32
    .lookupFunction<Int32 Function(IntPtr), int Function(int)>('closesocket');
final _wsaGetLastError =
    _ws2_32.lookupFunction<Int32 Function(), int Function()>(
        'WSAGetLastError');
final _inetNtop = _ws2_32.lookupFunction<
    Pointer<Utf8> Function(Int32, Pointer, Pointer<Utf8>, IntPtr),
    Pointer<Utf8> Function(int, Pointer, Pointer<Utf8>, int)>('inet_ntop');

// -- Friendly wrappers ---------------------------------------------------------

int getTickCount64() => _getTickCount64();
void sleepMs(int ms) => _sleep(ms);
void messageBeep() => _messageBeep(0);
int wsaGetLastError() => _wsaGetLastError();
int wsaSocket(int af, int type, int proto) => _wsaSocket(af, type, proto);
int wsaClose(int s) => _wsaClosesocket(s);
int wsaSendto(int s, Pointer buf, int len, int flags, Pointer to, int tolen) =>
    _wsaSendto(s, buf, len, flags, to, tolen);
int wsaSend(int s, Pointer buf, int len, int flags) =>
    _wsaSend(s, buf, len, flags);
int wsaRecv(int s, Pointer buf, int len, int flags) =>
    _wsaRecv(s, buf, len, flags);
int wsaConnect(int s, Pointer to, int tolen) => _wsaConnect(s, to, tolen);
int wsaSetsockopt(int s, int level, int name, Pointer val, int len) =>
    _wsaSetsockopt(s, level, name, val, len);
int icmpCreateFile() => _icmpCreateFile();
int icmp6CreateFile() => _icmp6CreateFile();
void icmpCloseHandle(int h) => _icmpCloseHandle(h);
/// Manual-reset event — an auto-reset event would have its signal
/// consumed by WaitForMultipleObjects before the caller can inspect
/// which probe completed.
int createEvent() => _createEventW(nullptr, 1, 0, nullptr);
void closeHandle(int h) => _closeHandle(h);
int waitForObjects(Pointer<IntPtr> handles, int count, int timeoutMs) =>
    _waitForMultipleObjects(count, handles, 0, timeoutMs);

int icmpSendEcho(int handle, int destAddr, Pointer request, int requestSize,
        Pointer<IP_OPTION_INFORMATION> options, Pointer reply, int replySize,
        int timeoutMs) =>
    _icmpSendEcho(
        handle, destAddr, request, requestSize, options, reply, replySize,
        timeoutMs);

/// Async variant used by the route job: fires the probe and returns once the
/// [event] handle is signalled (or `timeoutMs` elapses).
int icmpSendEcho2(int handle, int event, int destAddr, Pointer request,
        int requestSize, Pointer<IP_OPTION_INFORMATION> options, Pointer reply,
        int replySize, int timeoutMs) =>
    _icmpSendEcho2(handle, event, nullptr, nullptr, destAddr, request,
        requestSize, options, reply, replySize, timeoutMs);

int icmp6SendEcho2(int handle, Pointer<SOCKADDR_IN6> src,
        Pointer<SOCKADDR_IN6> dst, Pointer request, int requestSize,
        Pointer<IP_OPTION_INFORMATION> options, Pointer reply, int replySize,
        int timeoutMs) =>
    _icmp6SendEcho2(handle, 0, nullptr, nullptr, src, dst, request,
        requestSize, options, reply, replySize, timeoutMs);

int icmp6SendEcho2Async(int handle, int event, Pointer<SOCKADDR_IN6> src,
        Pointer<SOCKADDR_IN6> dst, Pointer request, int requestSize,
        Pointer<IP_OPTION_INFORMATION> options, Pointer reply, int replySize,
        int timeoutMs) =>
    _icmp6SendEcho2(handle, event, nullptr, nullptr, src, dst, request,
        requestSize, options, reply, replySize, timeoutMs);

/// Kernel neighbour table for [family] (AF_INET / AF_INET6).
List<Map<String, Object?>> ipNetTable(int family, String Function(int) ifName) {
  return using((arena) {
    final pp = arena<Pointer>();
    if (_getIpNetTable2(family, pp) != 0) return const <Map<String, Object?>>[];
    final table = pp.value;
    try {
      final count = table.cast<MIB_IPNET_TABLE2>().ref.NumEntries;
      final rows = table.cast<Uint8>() + 8;
      final out = <Map<String, Object?>>[];
      for (var i = 0; i < count; i++) {
        final row = (rows + i * sizeOf<MIB_IPNET_ROW2>())
            .cast<MIB_IPNET_ROW2>();
        final r = row.ref;
        // Usable entries only: Delay/Stale/Reachable/Permanent carry a
        // resolved link address; Incomplete/Unreachable rows don't.
        if (r.State < 3 || r.State > 6) continue;
        if (r.PhysicalAddressLength != 6) continue;
        final ip = sockaddrInetString(row.cast<SOCKADDR_INET>());
        if (ip == null || ip == '::1') continue;
        if (ip.startsWith('224.') ||
            ip == '255.255.255.255' ||
            ip.toLowerCase().startsWith('ff')) {
          continue;
        }
        final mac = macString(r.PhysicalAddress, 6);
        if (mac == '00:00:00:00:00:00' || mac == 'ff:ff:ff:ff:ff:ff') {
          continue;
        }
        final name = ifName(r.InterfaceIndex);
        out.add({
          'ip': ip,
          'mac': mac,
          if (name.isNotEmpty) 'interface': name,
        });
      }
      return out;
    } finally {
      _freeMibTable(table);
    }
  });
}

/// Per-interface counters via GetIfTable2, keyed by interface index.
Map<int, Map<String, Object?>> ifTableStats() {
  return using((arena) {
    final pp = arena<Pointer>();
    if (_getIfTable2(pp) != 0) return const {};
    final table = pp.value;
    try {
      final count = table.cast<MIB_IF_TABLE2>().ref.NumEntries;
      final rows = table.cast<Uint8>() + 8;
      final out = <int, Map<String, Object?>>{};
      for (var i = 0; i < count; i++) {
        final r = (rows + i * sizeOf<MIB_IF_ROW2>()).cast<MIB_IF_ROW2>().ref;
        final loopback = r.Type == 24; // IF_TYPE_SOFTWARE_LOOPBACK
        final up = r.OperStatus == 1; // IfOperStatusUp
        final running = up && r.MediaConnectState == 1;
        // Synthesize BSD-style if_flags bits the Dart model reads.
        var flags = 0;
        if (up) flags |= 0x1;
        if (running) flags |= 0x40;
        if (loopback) flags |= 0x8;
        out[r.InterfaceIndex] = {
          'index': r.InterfaceIndex,
          'flags': flags,
          'mtu': r.Mtu,
          'baudrate': r.ReceiveLinkSpeed,
          'type': r.Type,
          if (r.PhysicalAddressLength == 6)
            'mac': macString(r.PhysicalAddress, 6),
          'rxBytes': r.InOctets,
          'txBytes': r.OutOctets,
          'rxPackets': r.InUcastPkts + r.InNUcastPkts,
          'txPackets': r.OutUcastPkts + r.OutNUcastPkts,
          'rxErrors': r.InErrors,
          'txErrors': r.OutErrors,
          'rxQDrops': r.InDiscards,
          'collisions': 0,
        };
      }
      return out;
    } finally {
      _freeMibTable(table);
    }
  });
}

/// Best route to 8.8.8.8 — effectively the default route; returns the
/// gateway literal + interface index, or null when offline.
({String? gateway, int? ifIndex}) bestRouteV4() {
  return using((arena) {
    final dst = arena<SOCKADDR_INET>();
    dst.ref.si_family = afInet;
    dst.cast<Uint8>()[4] = 8;
    dst.cast<Uint8>()[5] = 8;
    dst.cast<Uint8>()[6] = 8;
    dst.cast<Uint8>()[7] = 8;
    final row = arena<MIB_IPFORWARD_ROW2>();
    final src = arena<SOCKADDR_INET>();
    final status = _getBestRoute2(nullptr, 0, nullptr, dst, 0, row, src);
    if (status != 0) return (gateway: null, ifIndex: null);
    // NextHop is the SOCKADDR_INET union at offset 44 in the row.
    final gw = sockaddrInetString(
        Pointer<SOCKADDR_INET>.fromAddress(row.address + 44));
    return (
      gateway: (gw == null || gw == '0.0.0.0') ? null : gw,
      ifIndex: row.ref.InterfaceIndex,
    );
  });
}

// -- sockaddr helpers ----------------------------------------------------------

/// Formats a SOCKADDR_INET / SOCKADDR_IN (or _IN6) pointer as a literal.
/// IPv6 link-locals gain a `%<scope>` suffix like the macOS side emits.
String? sockaddrInetString(Pointer<SOCKADDR_INET>? sa) {
  if (sa == null || sa == nullptr) return null;
  final raw = sa.cast<Uint8>();
  final family = raw[0] | (raw[1] << 8);
  if (family == afInet) {
    return '${raw[4]}.${raw[5]}.${raw[6]}.${raw[7]}';
  }
  if (family == afInet6) {
    final ip = inetNtopString(afInet6, raw + 8);
    if (ip == null) return null;
    final scope = (raw + 24).cast<Uint32>().value;
    final linkLocal = raw[8] == 0xfe && (raw[9] & 0xc0) == 0x80;
    return linkLocal && scope != 0 ? '$ip%$scope' : ip;
  }
  return null;
}

String? inetNtopString(int family, Pointer addrBytes) {
  return using((arena) {
    final buf = arena<Uint8>(64).cast<Utf8>();
    final r = _inetNtop(family, addrBytes, buf, 64);
    if (r == nullptr) return null;
    return buf.toDartString();
  });
}

/// sockaddr pointer (any family) → literal string; used for adapter
/// address lists where SOCKET_ADDRESS.lpSockaddr points at a variable-
/// length sockaddr.
String? sockaddrToString(Pointer sockAddr, int len) {
  if (sockAddr == nullptr || len <= 0) return null;
  final raw = sockAddr.cast<Uint8>();
  final family = raw[0] | (raw[1] << 8);
  if (family == afInet && len >= 16) {
    return '${raw[4]}.${raw[5]}.${raw[6]}.${raw[7]}';
  }
  if (family == afInet6 && len >= 28) {
    final ip = inetNtopString(afInet6, raw + 8);
    if (ip == null) return null;
    final scope = (raw + 24).cast<Uint32>().value;
    final linkLocal = raw[8] == 0xfe && (raw[9] & 0xc0) == 0x80;
    return linkLocal && scope != 0 ? '$ip%$scope' : ip;
  }
  return null;
}

String macString(Array<Uint8> bytes, int len) => [
      for (var i = 0; i < len; i++)
        bytes[i].toRadixString(16).padLeft(2, '0'),
    ].join(':');

String macStringFromBytes(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(':');

/// sockaddr_in6 for a Dart [InternetAddress] literal (+ optional scope).
Pointer<SOCKADDR_IN6> sockaddrIn6(Allocator alloc, InternetAddress addr,
    {int scopeId = 0, int port = 0}) {
  final sa = alloc<SOCKADDR_IN6>();
  sa.ref
    ..sin6_family = afInet6
    ..sin6_port = htons(port)
    ..sin6_flowinfo = 0
    ..sin6_scope_id = scopeId;
  final bytes = addr.rawAddress;
  for (var i = 0; i < 16; i++) {
    sa.ref.sin6_addr[i] = i < bytes.length ? bytes[i] : 0;
  }
  return sa;
}

int htons(int v) => ((v & 0xff) << 8) | ((v >> 8) & 0xff);
