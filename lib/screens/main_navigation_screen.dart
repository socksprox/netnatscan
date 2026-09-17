import 'package:flutter/material.dart';

import '../services/theme_manager.dart' as theme_manager;
import '../widgets/app_navigation.dart';
import 'connection_info_screen.dart';
import 'scan_screen.dart';

/// App shell: IndexedStack of tabs behind a responsive AppNavigation —
/// sidebar at >=1024px, bottom bar below. Tabs keep their own Scaffold
/// (and app bar), so each screen composes unchanged.
class MainNavigationScreen extends StatefulWidget {
  const MainNavigationScreen({super.key});

  @override
  State<MainNavigationScreen> createState() => _MainNavigationScreenState();
}

class _MainNavigationScreenState extends State<MainNavigationScreen> {
  int _currentIndex = 0;

  static const _items = [
    NavItemSpec(
      icon: Icons.radar_outlined,
      activeIcon: Icons.radar,
      label: 'Scan',
    ),
    NavItemSpec(
      icon: Icons.info_outlined,
      activeIcon: Icons.info,
      label: 'Connection',
    ),
  ];

  static const _tabs = [ScanScreen(), ConnectionInfoScreen()];

  void _cycleTheme() {
    final tm = theme_manager.ThemeManager();
    final next = switch (tm.themeMode) {
      theme_manager.ThemeMode.system => theme_manager.ThemeMode.light,
      theme_manager.ThemeMode.light => theme_manager.ThemeMode.dark,
      theme_manager.ThemeMode.dark => theme_manager.ThemeMode.system,
    };
    tm.setThemeMode(next);
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final desktop = AppNavigation.isDesktop(context);

    final stack = IndexedStack(index: _currentIndex, children: _tabs);
    final nav = AppNavigation(
      currentIndex: _currentIndex,
      onNavigate: (i) => setState(() => _currentIndex = i),
      items: _items,
      onCycleTheme: _cycleTheme,
    );

    return Scaffold(
      backgroundColor: isDark ? Colors.grey.shade900 : Colors.grey.shade50,
      body: desktop
          ? Row(children: [nav, Expanded(child: stack)])
          : Column(children: [Expanded(child: stack), nav]),
    );
  }
}
