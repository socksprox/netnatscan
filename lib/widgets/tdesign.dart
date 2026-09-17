import 'package:flutter/material.dart';

import '../services/theme_manager.dart' as theme_manager;

/// Local re-implementation of the small slice of the tdesign_flutter API the
/// shared components use (TDText / TDTheme / TDToast). Same look, no package.
class TDFont {
  final double size;
  final double lineHeight;

  const TDFont({required this.size, required this.lineHeight});
}

class TDThemeData {
  const TDThemeData();

  TDFont get fontTitleLarge => const TDFont(size: 18, lineHeight: 26);
  TDFont get fontTitleMedium => const TDFont(size: 16, lineHeight: 24);
  TDFont get fontBodyLarge => const TDFont(size: 16, lineHeight: 24);
  TDFont get fontBodyMedium => const TDFont(size: 14, lineHeight: 22);
  TDFont get fontBodySmall => const TDFont(size: 12, lineHeight: 20);

  Color get brandNormalColor => theme_manager.ThemeManager().themeColor;
}

class TDTheme {
  TDTheme._();
  static TDThemeData of(BuildContext context) => const TDThemeData();
}

class TDText extends StatelessWidget {
  final String data;
  final TDFont? font;
  final Color? textColor;
  final FontWeight? fontWeight;
  final int? maxLines;
  final TextOverflow? overflow;
  final TextAlign? textAlign;

  const TDText(
    this.data, {
    super.key,
    this.font,
    this.textColor,
    this.fontWeight,
    this.maxLines,
    this.overflow,
    this.textAlign,
  });

  @override
  Widget build(BuildContext context) {
    final f = font ?? TDTheme.of(context).fontBodyMedium;
    return Text(
      data,
      maxLines: maxLines,
      overflow: overflow,
      textAlign: textAlign,
      style: TextStyle(
        fontSize: f.size,
        height: f.lineHeight / f.size,
        color: textColor,
        fontWeight: fontWeight,
      ),
    );
  }
}

class TDToast {
  TDToast._();

  static OverlayEntry? _entry;

  static void showText(String message, {required BuildContext context}) =>
      _show(message, context, null);

  static void showSuccess(String message, {required BuildContext context}) =>
      _show(message, context, Icons.check_circle);

  static void showFail(String message, {required BuildContext context}) =>
      _show(message, context, Icons.error);

  /// TDesign-style toast: a small card that slides in under the top app
  /// bar, holds for a moment, then fades out. Replaces any toast already
  /// showing so rapid copies don't stack.
  static void _show(String message, BuildContext context, IconData? icon) {
    _entry?.remove();
    _entry = null;
    final overlay = Overlay.maybeOf(context);
    if (overlay == null) return;
    late final OverlayEntry entry;
    entry = OverlayEntry(
      builder: (_) => _TDToastView(
        message: message,
        icon: icon,
        onDone: () {
          if (_entry == entry) _entry = null;
          entry.remove();
        },
      ),
    );
    _entry = entry;
    overlay.insert(entry);
  }
}

class _TDToastView extends StatefulWidget {
  final String message;
  final IconData? icon;
  final VoidCallback onDone;

  const _TDToastView({
    required this.message,
    required this.icon,
    required this.onDone,
  });

  @override
  State<_TDToastView> createState() => _TDToastViewState();
}

class _TDToastViewState extends State<_TDToastView>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 180),
    reverseDuration: const Duration(milliseconds: 140),
  );
  late final Animation<Offset> _slide = Tween(
    begin: const Offset(0, -0.4),
    end: Offset.zero,
  ).animate(CurvedAnimation(parent: _controller, curve: Curves.easeOutCubic));

  @override
  void initState() {
    super.initState();
    _controller.forward();
    Future.delayed(const Duration(milliseconds: 1400), () async {
      if (!mounted) return;
      await _controller.reverse();
      if (mounted) widget.onDone();
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final icon = widget.icon;
    final iconColor = icon == Icons.error
        ? (isDark ? Colors.red.shade300 : Colors.red.shade600)
        : (isDark ? Colors.green.shade300 : Colors.green.shade600);
    return Positioned(
      // Just under the CustomAppBar (kToolbarHeight + 24).
      top: MediaQuery.of(context).padding.top + kToolbarHeight + 32,
      left: 0,
      right: 0,
      child: IgnorePointer(
        child: SlideTransition(
          position: _slide,
          child: FadeTransition(
            opacity: _controller,
            child: Center(
              child: Container(
                constraints: const BoxConstraints(maxWidth: 360),
                padding: const EdgeInsets.symmetric(
                  horizontal: 14,
                  vertical: 8,
                ),
                decoration: BoxDecoration(
                  color: isDark ? Colors.grey.shade800 : Colors.white,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: isDark ? Colors.grey.shade700 : Colors.grey.shade200,
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withValues(
                        alpha: isDark ? 0.3 : 0.08,
                      ),
                      offset: const Offset(0, 2),
                      blurRadius: 8,
                    ),
                  ],
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.center,
                  children: [
                    if (icon != null) ...[
                      Icon(icon, size: 16, color: iconColor),
                      const SizedBox(width: 8),
                    ],
                    Flexible(
                      child: Text(
                        widget.message,
                        style: TextStyle(
                          fontSize: 13,
                          height: 1.1,
                          // Overlay entries have no Material/DefaultTextStyle
                          // ancestor — without this, debug builds paint the
                          // fallback yellow double-underline under the text.
                          decoration: TextDecoration.none,
                          color: isDark
                              ? Colors.grey.shade200
                              : Colors.grey.shade800,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
