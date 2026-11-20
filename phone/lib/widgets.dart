// Building blocks shared by the screens.
import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'engine/model.dart';
import 'theme.dart';

/// The score as a ring that fills in the verdict's colour.
class ScoreRing extends StatelessWidget {
  final int score;
  final Verdict verdict;
  final double size;
  const ScoreRing({super.key, required this.score, required this.verdict, this.size = 150});

  @override
  Widget build(BuildContext context) {
    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0, end: score.toDouble()),
      duration: Duration(milliseconds: MediaQuery.of(context).disableAnimations ? 0 : 1100),
      curve: Curves.easeOutCubic,
      builder: (context, v, _) => SizedBox(
        width: size,
        height: size,
        child: CustomPaint(
          painter: _RingPainter(v / 100, C.verdict(verdict)),
          child: Center(child: Text('${v.round()}', style: TextStyle(fontSize: size * .3, fontWeight: FontWeight.w800, color: C.verdict(verdict)))),
        ),
      ),
    );
  }
}

class _RingPainter extends CustomPainter {
  final double t;
  final Color color;
  _RingPainter(this.t, this.color);
  @override
  void paint(Canvas canvas, Size size) {
    final r = size.width / 2 - 10;
    final c = size.center(Offset.zero);
    final track = Paint()..color = C.surface2..style = PaintingStyle.stroke..strokeWidth = 12;
    canvas.drawCircle(c, r, track);
    final arc = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = 12
      ..strokeCap = StrokeCap.round
      ..maskFilter = const MaskFilter.blur(BlurStyle.solid, 3);
    canvas.drawArc(Rect.fromCircle(center: c, radius: r), -math.pi / 2, 2 * math.pi * t.clamp(0.0, 1.0), false, arc);
  }

  @override
  bool shouldRepaint(_RingPainter old) => old.t != t || old.color != color;
}

/// One finding: severity, title, plain explanation.
class FindingTile extends StatelessWidget {
  final Finding f;
  final bool ar;
  final String severityLabel;
  const FindingTile({super.key, required this.f, required this.ar, required this.severityLabel});

  @override
  Widget build(BuildContext context) {
    final color = C.severity(f.severity);
    return Container(
      decoration: BoxDecoration(
        color: C.surface,
        borderRadius: BorderRadius.circular(16),
        border: BorderDirectional(start: BorderSide(color: color, width: 3), top: const BorderSide(color: C.line), end: const BorderSide(color: C.line), bottom: const BorderSide(color: C.line)),
      ),
      padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Expanded(child: Text(f.title(ar), style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 15.5))),
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
            decoration: BoxDecoration(color: color.withValues(alpha: .14), borderRadius: BorderRadius.circular(99)),
            child: Text(severityLabel, style: TextStyle(color: color, fontSize: 11.5, fontWeight: FontWeight.w700)),
          ),
        ]),
        const SizedBox(height: 6),
        Text(f.detail(ar), style: const TextStyle(color: C.muted, height: 1.45, fontSize: 14)),
      ]),
    );
  }
}

/// The file's randomness, part by part (0 = plain, 8 = random).
class EntropyStrip extends StatelessWidget {
  final List<double> values;
  const EntropyStrip({super.key, required this.values});
  @override
  Widget build(BuildContext context) => SizedBox(height: 56, child: CustomPaint(painter: _EntropyPainter(values), size: Size.infinite));
}

class _EntropyPainter extends CustomPainter {
  final List<double> v;
  _EntropyPainter(this.v);
  @override
  void paint(Canvas canvas, Size size) {
    if (v.isEmpty) return;
    final w = size.width / v.length;
    for (var i = 0; i < v.length; i++) {
      final t = (v[i] / 8).clamp(0.0, 1.0);
      final color = t > .9 ? C.pink : t > .7 ? C.violet : Color.lerp(const Color(0xFF1E3A8A), C.cyan, t / .7)!;
      final h = math.max(4.0, size.height * t);
      canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(i * w + .5, size.height - h, math.max(1, w - 1), h), const Radius.circular(2)), Paint()..color = color);
    }
  }

  @override
  bool shouldRepaint(_EntropyPainter old) => old.v != v;
}

class SectionTitle extends StatelessWidget {
  final String text;
  final Widget? trailing;
  const SectionTitle(this.text, {super.key, this.trailing});
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsetsDirectional.fromSTEB(4, 18, 4, 10),
        child: Row(children: [
          Expanded(child: Text(text, style: const TextStyle(color: C.muted, fontWeight: FontWeight.w700, fontSize: 13.5, letterSpacing: .3))),
          ?trailing,
        ]),
      );
}

/// A big tappable card with an icon, used on Home and Tools.
class ActionCard extends StatelessWidget {
  final IconData icon;
  final String title, subtitle;
  final Color tint;
  final VoidCallback onTap;
  const ActionCard({super.key, required this.icon, required this.title, required this.subtitle, required this.onTap, this.tint = C.cyan});

  @override
  Widget build(BuildContext context) => Material(
        color: C.surface,
        borderRadius: BorderRadius.circular(22),
        child: InkWell(
          borderRadius: BorderRadius.circular(22),
          onTap: onTap,
          child: Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(borderRadius: BorderRadius.circular(22), border: Border.all(color: C.line)),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(color: tint.withValues(alpha: .13), borderRadius: BorderRadius.circular(14)),
                child: Icon(icon, color: tint, size: 26),
              ),
              const SizedBox(height: 12),
              Text(title, style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 16)),
              const SizedBox(height: 4),
              Text(subtitle, style: const TextStyle(color: C.muted, fontSize: 13, height: 1.35)),
            ]),
          ),
        ),
      );
}

String agoText(DateTime when, bool ar) {
  final d = DateTime.now().difference(when);
  if (d.inMinutes < 1) return ar ? 'الآن' : 'just now';
  if (d.inHours < 1) return ar ? 'قبل ${d.inMinutes} د' : '${d.inMinutes} min ago';
  if (d.inDays < 1) return ar ? 'قبل ${d.inHours} س' : '${d.inHours} h ago';
  return ar ? 'قبل ${d.inDays} يوم' : '${d.inDays} d ago';
}
