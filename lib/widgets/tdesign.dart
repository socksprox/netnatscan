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

  static void showText(String message, {required BuildContext context}) =>
      _show(message, context, null);

  static void showSuccess(String message, {required BuildContext context}) =>
      _show(message, context, Icons.check_circle);

  static void showFail(String message, {required BuildContext context}) =>
      _show(message, context, Icons.error);

  static void _show(String message, BuildContext context, IconData? icon) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        SnackBar(
          behavior: SnackBarBehavior.floating,
          elevation: 0,
          backgroundColor: isDark ? Colors.grey.shade800 : Colors.black87,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          content: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (icon != null) ...[
                Icon(
                  icon,
                  size: 18,
                  color: icon == Icons.error
                      ? Colors.red.shade300
                      : Colors.green.shade300,
                ),
                const SizedBox(width: 8),
              ],
              Flexible(
                child: Text(
                  message,
                  style: const TextStyle(color: Colors.white, fontSize: 13),
                ),
              ),
            ],
          ),
        ),
      );
  }
}
