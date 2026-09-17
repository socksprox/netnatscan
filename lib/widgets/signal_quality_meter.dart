import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../services/theme_manager.dart' as theme_manager;
import 'tdesign.dart';

/// Quality word for a signal-to-noise ratio in dB.
String snrQuality(int snr) {
  if (snr >= 40) return 'Excellent';
  if (snr >= 25) return 'Good';
  if (snr >= 15) return 'Fair';
  return 'Weak';
}

/// Quality word for raw RSSI — fallback when the noise floor is unknown.
String rssiQuality(int rssi) {
  if (rssi >= -50) return 'Excellent';
  if (rssi >= -60) return 'Good';
  if (rssi >= -70) return 'Fair';
  return 'Weak';
}

/// One-line "Excellent · 54 dB SNR" summary; falls back to raw RSSI
/// when the noise floor is unavailable.
String signalQualityLabel(int? rssi, int? noise) {
  if (rssi != null && noise != null) {
    final snr = rssi - noise;
    return '${snrQuality(snr)} · $snr dB SNR';
  }
  if (rssi != null) return '${rssiQuality(rssi)} · $rssi dBm';
  return '—';
}

/// Color for a quality level — SNR-based when the floor is known,
/// RSSI-based otherwise; grey when there's no signal data at all.
Color signalQualityColor(int? rssi, int? noise) {
  final quality = switch ((rssi, noise)) {
    (int r, int n) => snrQuality(r - n),
    (int r, null) => rssiQuality(r),
    _ => '',
  };
  return switch (quality) {
    'Excellent' => Colors.green,
    'Good' => Colors.lightGreen,
    'Fair' => Colors.orange,
    'Weak' => Colors.red,
    _ => Colors.grey,
  };
}

/// Self-explaining signal graph: plots the noise floor and the received
/// signal on a shared dBm scale — the bracketed distance between them is
/// literally what SNR means. Pair with [signalQualityLabel] as the row
/// value and this meter underneath.
class SignalQualityMeter extends StatelessWidget {
  final int rssi;
  final int? noise;

  const SignalQualityMeter({super.key, required this.rssi, this.noise});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final accent = theme_manager.ThemeManager().themeColor;
    final noiseColor = isDark ? Colors.grey.shade500 : Colors.grey.shade400;
    final captionColor = isDark ? Colors.grey.shade400 : Colors.grey.shade600;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SizedBox(
          height: 48,
          child: CustomPaint(
            painter: _SignalScalePainter(
              rssi: rssi,
              noise: noise,
              accent: accent,
              noiseColor: noiseColor,
            ),
          ),
        ),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            _legendChip(context, accent, 'signal $rssi dBm', captionColor),
            if (noise != null) ...[
              const SizedBox(width: 14),
              _legendChip(
                context,
                noiseColor,
                'noise $noise dBm',
                captionColor,
              ),
            ],
          ],
        ),
      ],
    );
  }

  Widget _legendChip(
    BuildContext context,
    Color color,
    String text,
    Color textColor,
  ) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 6,
          height: 6,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 4),
        TDText(
          text,
          font: TDTheme.of(context).fontBodySmall,
          textColor: textColor,
        ),
      ],
    );
  }
}

/// The dBm number line (−100 … −20): a short grey marker for the noise
/// floor, a taller accent marker for the signal, and a dimension bracket
/// spanning the gap labeled "N dB SNR".
class _SignalScalePainter extends CustomPainter {
  final int rssi;
  final int? noise;
  final Color accent;
  final Color noiseColor;

  static const double _minDbm = -100;
  static const double _maxDbm = -20;
  static const double _axisY = 38;
  static const double _bracketY = 16;
  static const double _signalTop = 24;
  static const double _noiseTop = 30;

  _SignalScalePainter({
    required this.rssi,
    required this.noise,
    required this.accent,
    required this.noiseColor,
  });

  double _x(int dbm, double w) {
    final t = ((dbm - _minDbm) / (_maxDbm - _minDbm)).clamp(0.0, 1.0);
    return 6 + t * (w - 12);
  }

  @override
  void paint(Canvas canvas, Size size) {
    final w = size.width;
    final xR = _x(rssi, w);
    final axisPaint = Paint()
      ..color = noiseColor.withValues(alpha: 0.6)
      ..strokeWidth = 1.5
      ..strokeCap = StrokeCap.round;

    if (noise != null) {
      final xN = _x(noise!, w);
      final snr = rssi - noise!;

      // Dimension bracket spanning noise → signal: the gap IS the SNR.
      final bracketPaint = Paint()
        ..color = accent.withValues(alpha: 0.6)
        ..strokeWidth = 1;
      final left = math.min(xN, xR);
      final right = math.max(xN, xR);
      canvas.drawLine(
        Offset(left, _bracketY),
        Offset(right, _bracketY),
        bracketPaint,
      );
      canvas.drawLine(
        Offset(xN, _bracketY),
        Offset(xN, _bracketY + 4),
        bracketPaint,
      );
      canvas.drawLine(
        Offset(xR, _bracketY),
        Offset(xR, _bracketY + 4),
        bracketPaint,
      );

      final tp = TextPainter(
        text: TextSpan(
          text: '$snr dB SNR',
          style: TextStyle(
            color: accent,
            fontSize: 11,
            fontWeight: FontWeight.w600,
          ),
        ),
        textDirection: TextDirection.ltr,
      )..layout();
      final tx = ((left + right) / 2 - tp.width / 2).clamp(0.0, w - tp.width);
      tp.paint(canvas, Offset(tx, 1));

      // Noise-floor marker.
      canvas.drawLine(
        Offset(xN, _axisY),
        Offset(xN, _noiseTop),
        Paint()
          ..color = noiseColor
          ..strokeWidth = 2
          ..strokeCap = StrokeCap.round,
      );
    }

    // Signal marker — stands tall above the noise floor.
    final signalPaint = Paint()
      ..color = accent
      ..strokeWidth = 2
      ..strokeCap = StrokeCap.round;
    canvas.drawLine(Offset(xR, _axisY), Offset(xR, _signalTop), signalPaint);
    canvas.drawCircle(Offset(xR, _signalTop), 3, Paint()..color = accent);

    // Axis with end ticks.
    canvas.drawLine(Offset(6, _axisY), Offset(w - 6, _axisY), axisPaint);
    canvas.drawLine(Offset(6, _axisY), Offset(6, _axisY + 4), axisPaint);
    canvas.drawLine(
      Offset(w - 6, _axisY),
      Offset(w - 6, _axisY + 4),
      axisPaint,
    );
  }

  @override
  bool shouldRepaint(_SignalScalePainter old) =>
      old.rssi != rssi ||
      old.noise != noise ||
      old.accent != accent ||
      old.noiseColor != noiseColor;
}
