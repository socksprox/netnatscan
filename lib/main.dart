import 'package:flutter/material.dart';

import 'screens/main_navigation_screen.dart';
import 'services/theme_manager.dart' as theme_manager;

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await theme_manager.ThemeManager().init();
  runApp(const NetNatScanApp());
}

class NetNatScanApp extends StatefulWidget {
  const NetNatScanApp({super.key});

  @override
  State<NetNatScanApp> createState() => _NetNatScanAppState();
}

class _NetNatScanAppState extends State<NetNatScanApp> {
  @override
  void initState() {
    super.initState();
    theme_manager.ThemeManager().addListener(_onThemeChanged);
  }

  @override
  void dispose() {
    theme_manager.ThemeManager().removeListener(_onThemeChanged);
    super.dispose();
  }

  void _onThemeChanged() => setState(() {});

  @override
  Widget build(BuildContext context) {
    final tm = theme_manager.ThemeManager();
    final brightness = tm.getBrightness(context);

    return MaterialApp(
      title: 'netnatscan',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: tm.themeColor,
          brightness: Brightness.light,
        ),
        useMaterial3: true,
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: tm.themeColor,
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      themeMode: brightness == Brightness.dark
          ? ThemeMode.dark
          : ThemeMode.light,
      home: const MainNavigationScreen(),
    );
  }
}
