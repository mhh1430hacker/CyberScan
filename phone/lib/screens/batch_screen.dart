// Several shared files, checked together: the most serious first.
import 'package:flutter/material.dart';

import '../engine/model.dart';
import '../main.dart';
import '../theme.dart';
import 'home_screen.dart';

class BatchScreen extends StatelessWidget {
  final List<ScanResult> results;
  const BatchScreen({super.key, required this.results});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    final bad = results.where((r) => r.verdict == Verdict.suspicious).length;
    return Scaffold(
      appBar: AppBar(title: Text(s.sharedResults)),
      body: SafeArea(
        child: ListView(padding: const EdgeInsets.fromLTRB(16, 8, 16, 24), children: [
          Row(children: [
            Icon(bad > 0 ? Icons.gpp_maybe_rounded : Icons.verified_user_rounded, color: bad > 0 ? C.bad : C.ok),
            const SizedBox(width: 8),
            Expanded(
              child: Text('${results.length} ${s.checks} · $bad ${s.warnings}',
                  style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 16)),
            ),
          ]),
          const SizedBox(height: 12),
          for (final r in results) ...[HistoryRow(result: r), const SizedBox(height: 8)],
        ]),
      ),
    );
  }
}
