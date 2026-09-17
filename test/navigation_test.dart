import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:netnatscan/main.dart';
import 'package:netnatscan/screens/connection_info_screen.dart';

const _channel = MethodChannel('netnatscan/network');

/// Canned getConnectionInfo payload — the shape NetworkPlugin returns.
const _connInfo = {
  'hostname': 'testmac',
  'primaryInterface': 'en0',
  'networkType': 'wifi',
  'defaultGateway': '192.168.1.1',
  'ipv6Gateway': 'fe80::1',
  'wifi': {
    'interfaceName': 'en0',
    'ssid': 'TestNet',
    'ssidAvailable': true,
    'bssid': 'aa:bb:cc:dd:ee:ff',
    'security': 'WPA2 Personal',
    'securityDetail': 'WPA2-PSK (CCMP-128)',
    'rssi': -50,
    'noise': -90,
    'transmitRate': 866.0,
    'channel': 36,
    'channelBand': '5 GHz',
    'channelWidth': '80 MHz',
    'phyMode': '802.11ax',
    'countryCode': 'DE',
    'mac': '11:22:33:44:55:66',
  },
  'interfaces': {
    'en0': {
      'index': 14,
      'flags': 34915,
      'mtu': 1500,
      'baudrate': 561600000,
      'type': 6,
      'rxBytes': 10485760,
      'txBytes': 5242880,
      'rxPackets': 10000,
      'txPackets': 8000,
      'rxErrors': 0,
      'txErrors': 0,
      'rxQDrops': 0,
      'collisions': 0,
    },
  },
  'dnsServers': ['192.168.1.1'],
  'searchDomains': ['lan'],
  'proxies': <String, dynamic>{},
  'dhcp': {
    'LeaseStartTime': 1700000000.0,
    'LeaseExpirationTime': 1700086400.0,
    'ServerIdentifier': '192.168.1.1',
    'Router': '192.168.1.1',
  },
  'bootTime': 1700000000.0,
  'uptimeSeconds': 86400.0,
};

const _netInfo = {
  'interfaces': [
    {
      'name': 'en0',
      'ip': '192.168.1.42',
      'netmask': '255.255.255.0',
      'mac': '11:22:33:44:55:66',
      'isUp': true,
      'isLoopback': false,
      'ipv6': ['fe80::1%en0'],
    },
  ],
  'defaultGateway': '192.168.1.1',
  'defaultInterface': 'en0',
};

/// Canned getWifiNetworks payload — the shape NetworkPlugin returns.
const _wifiNets = {
  'interfaceName': 'en0',
  'networks': [
    {
      'ssid': 'CoffeeShop-5G',
      'bssid': 'aa:bb:cc:00:11:22',
      'rssi': -42,
      'noise': -90,
      'channel': 36,
      'band': '5 GHz',
      'width': '80 MHz',
      'security': 'WPA2 Personal',
      'ibss': false,
      'isCurrent': true,
      'securityDetail': 'WPA2-PSK (CCMP-128)',
      'phyFastest': '802.11ax',
      'phySupported': 'n/ac/ax',
      'signalStrength': 0.97,
      'channelSpec': '5g36/80',
      'maxStreams': 2,
      'tags': ['WPS'],
    },
    {
      'ssid': 'Neighbor-24',
      'bssid': '11:22:33:44:55:66',
      'rssi': -78,
      'noise': -88,
      'channel': 6,
      'band': '2.4 GHz',
      'width': '20 MHz',
      'security': 'WPA2/WPA3 Personal',
      'ibss': false,
      'isCurrent': false,
    },
    {
      'ssid': null,
      'bssid': '22:33:44:55:66:77',
      'rssi': -91,
      'noise': -85,
      'channel': 1,
      'band': '2.4 GHz',
      'width': '20 MHz',
      'security': 'WPA2 Personal',
      'ibss': false,
      'isCurrent': false,
    },
  ],
};

void _mockChannel() {
  TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .setMockMethodCallHandler(_channel, (call) async {
        return switch (call.method) {
          'getConnectionInfo' => _connInfo,
          'getNetworkInfo' => _netInfo,
          'getWifiNetworks' => _wifiNets,
          'getArpTable' || 'getNdpTable' => <Map>[],
          _ => null,
        };
      });
}

void main() {
  setUp(_mockChannel);

  testWidgets('Wide window shows sidebar with both tabs', (tester) async {
    tester.view.physicalSize = const Size(1400, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(const NetNatScanApp());
    await tester.pump();

    // Sidebar brand + both nav labels, no bottom bar.
    expect(find.text('netnatscan'), findsOneWidget);
    expect(find.text('Scan'), findsWidgets);
    expect(find.text('Connection'), findsWidgets);
    expect(find.byType(BottomNavigationBar), findsNothing);
    // Tabs have no app bar — the sidebar shows the selection instead.
    expect(find.byType(AppBar), findsNothing);

    // Unmount (cancels the refresh ticker + passive mDNS loop), then
    // drain the scan's remaining timers in fake time.
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 60));
  });

  testWidgets('Narrow window shows bottom navigation', (tester) async {
    tester.view.physicalSize = const Size(800, 600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(const NetNatScanApp());
    await tester.pump();

    expect(find.byType(BottomNavigationBar), findsOneWidget);
    expect(find.text('netnatscan'), findsNothing); // no sidebar brand

    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 60));
  });

  testWidgets('Connection tab renders Wi-Fi and network details', (
    tester,
  ) async {
    // Tall surface so every card is inside the ListView's build extent.
    tester.view.physicalSize = const Size(800, 2200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(const NetNatScanApp());
    await tester.pump();

    // The label exists in the nav bar even while the scan tab shows —
    // tap the bottom-bar item specifically.
    await tester.tap(
      find.descendant(
        of: find.byType(BottomNavigationBar),
        matching: find.text('Connection'),
      ),
    );
    await tester.pump();
    // Let the service's channel round-trips land.
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pump(const Duration(milliseconds: 300));

    expect(find.text('Connection'), findsWidgets);
    expect(find.text('TestNet'), findsOneWidget);
    expect(find.text('WPA2-PSK (CCMP-128)'), findsOneWidget);
    // Rows below the painted viewport: find.text's default skipOffstage
    // skips lazy-built ListView children outside the paint extent, so
    // scope the match to the connection screen instead.
    Finder inConnScreen(String text) => find.descendant(
      of: find.byType(ConnectionInfoScreen),
      matching: find.text(text, skipOffstage: false),
      skipOffstage: false,
    );
    // 'Wi-Fi' matches both the nav label and the Type row — scope it.
    expect(inConnScreen('Wi-Fi'), findsOneWidget);
    expect(inConnScreen('192.168.1.42'), findsOneWidget);
    expect(inConnScreen('DNS & Proxy'), findsOneWidget);
    expect(inConnScreen('Traffic (since boot)'), findsOneWidget);
    expect(inConnScreen('10.0 MB (10.0K packets)'), findsOneWidget);

    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 60));
  });

  testWidgets('Wi-Fi tab lists nearby networks', (tester) async {
    tester.view.physicalSize = const Size(800, 1600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(const NetNatScanApp());
    await tester.pump();

    await tester.tap(
      find.descendant(
        of: find.byType(BottomNavigationBar),
        matching: find.text('Wi-Fi'),
      ),
    );
    await tester.pump();
    // Let the service's channel round-trip + OUI load land.
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pump(const Duration(milliseconds: 300));

    // Connected network first (sorted), then strongest RSSI.
    expect(find.text('CoffeeShop-5G'), findsOneWidget);
    expect(find.text('Connected'), findsOneWidget);
    expect(find.text('-42 dBm'), findsOneWidget);
    // Private enrichment lands: precise security + PHY + tags.
    expect(find.textContaining('WPA2-PSK (CCMP-128)'), findsOneWidget);
    expect(find.textContaining('802.11ax'), findsOneWidget);
    expect(find.text('Neighbor-24'), findsOneWidget);
    expect(find.text('Hidden network'), findsOneWidget);
    expect(find.textContaining('3 networks nearby'), findsOneWidget);

    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump(const Duration(seconds: 60));
  });
}
