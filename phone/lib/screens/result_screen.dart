// One result: verdict and score, what was found and why, the file's inside, the details, share.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:share_plus/share_plus.dart';

import '../engine/model.dart';
import '../main.dart';
import '../strings.dart';
import '../theme.dart';
import '../widgets.dart';

class ResultScreen extends StatelessWidget {
  final ScanResult result;
  const ResultScreen({super.key, required this.result});

  String _report(bool ar, S s) {
    final b = StringBuffer()
      ..writeln('CyberScan · ${s.verdict(result.verdict.name)} · ${result.score}/100')
      ..writeln(result.target)
      ..writeln();
    for (final f in result.sorted) {
      b.writeln('• ${f.title(ar)} (${s.sev(f.severity.name)})');
      b.writeln('  ${f.detail(ar)}');
    }
    b.writeln();
    for (final fact in result.facts) {
      b.writeln('${ar ? fact.labelAr : fact.labelEn}: ${fact.value}');
    }
    return b.toString();
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s, ar = app.ar;
    final color = C.verdict(result.verdict);
    final shown = result.sorted.where((f) => f.weight > 0 || f.severity != Severity.info).toList();
    final notes = result.sorted.where((f) => f.weight == 0 && f.severity == Severity.info).toList();
    return Scaffold(
      appBar: AppBar(title: Text(s.appName, style: const TextStyle(fontWeight: FontWeight.w700))),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 4, 16, 32),
        children: [
          // ---- the verdict
          Container(
            padding: const EdgeInsets.fromLTRB(18, 22, 18, 20),
            decoration: BoxDecoration(
              color: C.surface,
              borderRadius: BorderRadius.circular(26),
              border: Border.all(color: color.withValues(alpha: .45)),
              boxShadow: [BoxShadow(color: color.withValues(alpha: .18), blurRadius: 40, spreadRadius: -10)],
            ),
            child: Column(children: [
              ScoreRing(score: result.score, verdict: result.verdict),
              const SizedBox(height: 14),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
                decoration: BoxDecoration(color: color.withValues(alpha: .14), borderRadius: BorderRadius.circular(99)),
                child: Text(s.verdict(result.verdict.name), style: TextStyle(color: color, fontWeight: FontWeight.w800, fontSize: 15)),
              ),
              const SizedBox(height: 12),
              Text(s.advice(result.verdict.name, result.kind.name), textAlign: TextAlign.center, style: const TextStyle(fontSize: 15.5, height: 1.5)),
              const SizedBox(height: 12),
              Text(result.target, textAlign: TextAlign.center, maxLines: 2, overflow: TextOverflow.ellipsis, textDirection: TextDirection.ltr,
                  style: const TextStyle(color: C.muted, fontFamily: 'monospace', fontSize: 12.5)),
              const SizedBox(height: 4),
              Text(s.took(result.elapsedMs), style: const TextStyle(color: C.muted, fontSize: 12)),
            ]),
          ),
          const SizedBox(height: 12),
          Text(s.scoreNote, textAlign: TextAlign.center, style: const TextStyle(color: C.muted, fontSize: 12.5)),

          // ---- findings
          SectionTitle(s.findings),
          if (shown.isEmpty)
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: C.surface, borderRadius: BorderRadius.circular(16), border: Border.all(color: C.line)),
              child: Row(children: [const Icon(Icons.verified_outlined, color: C.ok), const SizedBox(width: 10), Expanded(child: Text(s.noFindings))]),
            ),
          for (final f in [...shown, ...notes]) ...[FindingTile(f: f, ar: ar, severityLabel: s.sev(f.severity.name)), const SizedBox(height: 8)],

          // ---- inside the file
          if (result.entropyMap.length > 1) ...[
            SectionTitle(s.insideFile),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(color: C.surface, borderRadius: BorderRadius.circular(16), border: Border.all(color: C.line)),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                EntropyStrip(values: result.entropyMap),
                const SizedBox(height: 8),
                Text(s.insideNote, style: const TextStyle(color: C.muted, fontSize: 12.5)),
              ]),
            ),
          ],

          // ---- details
          SectionTitle(s.details),
          Container(
            decoration: BoxDecoration(color: C.surface, borderRadius: BorderRadius.circular(16), border: Border.all(color: C.line)),
            child: Column(children: [
              for (final (i, fact) in result.facts.indexed) ...[
                if (i > 0) const Divider(),
                ListTile(
                  dense: true,
                  title: Text(ar ? fact.labelAr : fact.labelEn, style: const TextStyle(color: C.muted, fontSize: 13)),
                  subtitle: Text(fact.value, textDirection: fact.value.contains(RegExp(r'[؀-ۿ]')) ? null : TextDirection.ltr,
                      style: const TextStyle(color: C.ink, fontSize: 14, fontFamily: 'monospace')),
                  trailing: fact.value.length > 24 ? const Icon(Icons.copy_rounded, size: 18, color: C.muted) : null,
                  onTap: fact.value.length > 24
                      ? () {
                          Clipboard.setData(ClipboardData(text: fact.value));
                          ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(s.copied), duration: const Duration(seconds: 1)));
                        }
                      : null,
                ),
              ],
            ]),
          ),
          const SizedBox(height: 18),
          Row(children: [
            Expanded(
              child: OutlinedButton.icon(
                onPressed: () => SharePlus.instance.share(ShareParams(text: _report(ar, s), subject: 'CyberScan')),
                icon: const Icon(Icons.ios_share_rounded),
                label: Text(s.share),
                style: OutlinedButton.styleFrom(padding: const EdgeInsets.symmetric(vertical: 14), side: const BorderSide(color: C.line), foregroundColor: C.ink),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: FilledButton(
                onPressed: () => Navigator.of(context).pop(),
                style: FilledButton.styleFrom(padding: const EdgeInsets.symmetric(vertical: 14), backgroundColor: C.cyan, foregroundColor: C.bg),
                child: Text(s.checkAnother, style: const TextStyle(fontWeight: FontWeight.w700)),
              ),
            ),
          ]),
          const SizedBox(height: 16),
          Text(s.limits, textAlign: TextAlign.center, style: const TextStyle(color: C.muted, fontSize: 12, height: 1.5)),
        ],
      ),
    );
  }
}
