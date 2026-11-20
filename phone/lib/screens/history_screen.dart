// History: every saved check, searchable and filterable, kept only on this phone.
import 'package:flutter/material.dart';

import '../engine/model.dart';
import '../main.dart';
import '../theme.dart';
import 'home_screen.dart';

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});
  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  Verdict? _filter;
  String _q = '';

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    final list = app.history.where((r) => (_filter == null || r.verdict == _filter) && (_q.isEmpty || r.target.toLowerCase().contains(_q) || (r.sha256 ?? '').contains(_q))).toList();
    return SafeArea(
      bottom: false,
      child: CustomScrollView(slivers: [
        SliverPadding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
          sliver: SliverList.list(children: [
            Row(children: [
              Expanded(child: Text(s.navHistory, style: const TextStyle(fontSize: 30, fontWeight: FontWeight.w800))),
              if (app.history.isNotEmpty)
                IconButton(
                  tooltip: s.clearAll,
                  icon: const Icon(Icons.delete_sweep_outlined, color: C.muted),
                  onPressed: () async {
                    final ok = await showDialog<bool>(
                      context: context,
                      builder: (c) => AlertDialog(
                        backgroundColor: C.surface,
                        content: Text(s.clearConfirm),
                        actions: [
                          TextButton(onPressed: () => Navigator.pop(c, false), child: Text(s.cancel)),
                          TextButton(onPressed: () => Navigator.pop(c, true), child: Text(s.remove, style: const TextStyle(color: C.bad))),
                        ],
                      ),
                    );
                    if (ok == true) app.clearHistory();
                  },
                ),
            ]),
            if (app.history.isNotEmpty) ...[
              const SizedBox(height: 12),
              TextField(decoration: InputDecoration(hintText: s.search, prefixIcon: const Icon(Icons.search_rounded, color: C.muted)), onChanged: (v) => setState(() => _q = v.trim().toLowerCase())),
              const SizedBox(height: 10),
              SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(children: [
                  for (final (v, label) in [(null, s.all), (Verdict.suspicious, s.verdict('suspicious')), (Verdict.review, s.verdict('review')), (Verdict.clear, s.verdict('clear'))])
                    Padding(
                      padding: const EdgeInsetsDirectional.only(end: 8),
                      child: ChoiceChip(
                        label: Text(label),
                        selected: _filter == v,
                        onSelected: (_) => setState(() => _filter = v),
                        selectedColor: C.cyan.withValues(alpha: .18),
                        backgroundColor: C.surface,
                        side: const BorderSide(color: C.line),
                        labelStyle: TextStyle(color: _filter == v ? C.cyan : C.ink),
                        showCheckmark: false,
                      ),
                    ),
                ]),
              ),
              const SizedBox(height: 12),
            ],
          ]),
        ),
        if (app.history.isEmpty)
          SliverFillRemaining(
            hasScrollBody: false,
            child: Padding(
              padding: const EdgeInsets.all(32),
              child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
                const Icon(Icons.history_rounded, size: 56, color: C.muted),
                const SizedBox(height: 12),
                Text(s.historyEmpty, textAlign: TextAlign.center, style: const TextStyle(color: C.muted)),
              ]),
            ),
          )
        else
          SliverPadding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
            sliver: SliverList.separated(
              itemCount: list.length,
              separatorBuilder: (_, _) => const SizedBox(height: 8),
              itemBuilder: (_, i) => HistoryRow(
                result: list[i],
                onDelete: () {
                  app.removeAt(list[i]);
                  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(s.removed), duration: const Duration(seconds: 1)));
                },
              ),
            ),
          ),
      ]),
    );
  }
}
