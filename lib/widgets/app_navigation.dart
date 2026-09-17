import 'package:flutter/material.dart';

import '../services/theme_manager.dart' as theme_manager;
import 'tdesign.dart';

class NavItemSpec {
  final IconData icon;
  final IconData activeIcon;
  final String label;

  const NavItemSpec({
    required this.icon,
    required this.activeIcon,
    required this.label,
  });
}

/// Responsive app navigation modeled on the shadowfly-admin-app pattern:
/// a branded left sidebar at desktop widths (>=1024px), and a bottom
/// navigation bar below that. Selection state uses the theme accent;
/// outlined icons become filled on the active item.
class AppNavigation extends StatelessWidget {
  static const desktopBreakpoint = 1024.0;

  final int currentIndex;
  final ValueChanged<int> onNavigate;
  final List<NavItemSpec> items;
  final VoidCallback? onCycleTheme;

  const AppNavigation({
    super.key,
    required this.currentIndex,
    required this.onNavigate,
    required this.items,
    this.onCycleTheme,
  });

  static bool isDesktop(BuildContext context) =>
      MediaQuery.of(context).size.width >= desktopBreakpoint;

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return isDesktop(context)
        ? _buildSidebar(context, isDark)
        : _buildBottomBar(context, isDark);
  }

  // --- Sidebar (>=1024px) -------------------------------------------------

  Widget _buildSidebar(BuildContext context, bool isDark) {
    final themeColor = theme_manager.ThemeManager().themeColor;
    final background = isDark ? Colors.grey.shade900 : Colors.white;
    final border = isDark ? Colors.grey.shade800 : Colors.grey.shade200;

    return Container(
      width: 200,
      height: double.infinity,
      decoration: BoxDecoration(
        color: background,
        border: Border(right: BorderSide(color: border)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.25 : 0.04),
            blurRadius: 10,
            offset: const Offset(5, 0),
          ),
        ],
      ),
      child: SafeArea(
        right: false,
        bottom: false,
        child: Column(
          children: [
            SizedBox(
              height: 80,
              child: Padding(
                padding: const EdgeInsets.only(top: 12),
                child: Center(
                  child: TDText(
                    'netnatscan',
                    font: TDTheme.of(context).fontTitleLarge,
                    textColor: themeColor,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ),
            Divider(height: 1, color: border),
            Expanded(
              child: ListView(
                padding: EdgeInsets.zero,
                children: [
                  for (var i = 0; i < items.length; i++)
                    _buildSidebarItem(items[i], i, isDark, themeColor),
                ],
              ),
            ),
            if (onCycleTheme != null) _buildThemeButton(isDark, border),
          ],
        ),
      ),
    );
  }

  Widget _buildSidebarItem(
    NavItemSpec item,
    int index,
    bool isDark,
    Color themeColor,
  ) {
    final isSelected = index == currentIndex;
    final iconColor = isSelected
        ? themeColor
        : (isDark ? Colors.grey.shade400 : Colors.grey.shade600);
    final textColor = isSelected
        ? (isDark ? Colors.white : Colors.black)
        : (isDark ? Colors.grey.shade400 : Colors.grey.shade600);

    return Container(
      width: double.infinity,
      margin: const EdgeInsets.symmetric(vertical: 4, horizontal: 8),
      decoration: BoxDecoration(
        color: isSelected
            ? themeColor.withValues(alpha: 0.08)
            : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: () => onNavigate(index),
          borderRadius: BorderRadius.circular(8),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            child: Row(
              children: [
                Icon(
                  isSelected ? item.activeIcon : item.icon,
                  color: iconColor,
                  size: 22,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    item.label,
                    style: TextStyle(
                      color: textColor,
                      fontWeight: isSelected
                          ? FontWeight.bold
                          : FontWeight.normal,
                      fontSize: 14,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildThemeButton(bool isDark, Color border) {
    final tm = theme_manager.ThemeManager();
    return Container(
      decoration: BoxDecoration(
        border: Border(top: BorderSide(color: border)),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onCycleTheme,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            child: Row(
              children: [
                Icon(
                  switch (tm.themeMode) {
                    theme_manager.ThemeMode.system =>
                      Icons.brightness_auto_outlined,
                    theme_manager.ThemeMode.light => Icons.light_mode_outlined,
                    theme_manager.ThemeMode.dark => Icons.dark_mode_outlined,
                  },
                  color: isDark ? Colors.grey.shade400 : Colors.grey.shade600,
                  size: 20,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    switch (tm.themeMode) {
                      theme_manager.ThemeMode.system => 'System theme',
                      theme_manager.ThemeMode.light => 'Light theme',
                      theme_manager.ThemeMode.dark => 'Dark theme',
                    },
                    style: TextStyle(
                      color: isDark
                          ? Colors.grey.shade400
                          : Colors.grey.shade600,
                      fontSize: 14,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  // --- Bottom navigation (<1024px) ----------------------------------------

  Widget _buildBottomBar(BuildContext context, bool isDark) {
    final themeColor = theme_manager.ThemeManager().themeColor;
    final border = isDark ? Colors.grey.shade800 : Colors.grey.shade200;

    return Container(
      decoration: BoxDecoration(
        color: isDark ? Colors.grey.shade900 : Colors.white,
        border: Border(top: BorderSide(color: border)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.25 : 0.04),
            blurRadius: 10,
            offset: const Offset(0, -5),
          ),
        ],
      ),
      child: Theme(
        data: Theme.of(context).copyWith(
          splashColor: Colors.transparent,
          highlightColor: Colors.transparent,
          hoverColor: Colors.transparent,
        ),
        child: BottomNavigationBar(
          type: BottomNavigationBarType.fixed,
          enableFeedback: false,
          currentIndex: currentIndex,
          onTap: onNavigate,
          backgroundColor: Colors.transparent,
          elevation: 0,
          selectedItemColor: themeColor,
          unselectedItemColor: isDark
              ? Colors.grey.shade400
              : Colors.grey.shade600,
          selectedFontSize: 12,
          unselectedFontSize: 12,
          items: [
            for (final item in items)
              BottomNavigationBarItem(
                icon: Icon(item.icon),
                activeIcon: Icon(item.activeIcon),
                label: item.label,
              ),
          ],
        ),
      ),
    );
  }
}

/// Icon-only theme cycler for tab app bars — shown in the narrow layout
/// where the sidebar's theme row isn't on screen.
class ThemeCycleButton extends StatelessWidget {
  const ThemeCycleButton({super.key});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final tm = theme_manager.ThemeManager();
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: () => tm.setThemeMode(switch (tm.themeMode) {
          theme_manager.ThemeMode.system => theme_manager.ThemeMode.light,
          theme_manager.ThemeMode.light => theme_manager.ThemeMode.dark,
          theme_manager.ThemeMode.dark => theme_manager.ThemeMode.system,
        }),
        borderRadius: BorderRadius.circular(8),
        child: Padding(
          padding: const EdgeInsets.all(8),
          child: Icon(
            switch (tm.themeMode) {
              theme_manager.ThemeMode.system => Icons.brightness_auto_outlined,
              theme_manager.ThemeMode.light => Icons.light_mode_outlined,
              theme_manager.ThemeMode.dark => Icons.dark_mode_outlined,
            },
            color: isDark ? Colors.white : Colors.black,
            size: 20,
          ),
        ),
      ),
    );
  }
}
