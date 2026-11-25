// Runs a check off the interface thread (an isolate), saves it and opens the result.
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'app_state.dart';
import 'engine/file_scan.dart';
import 'engine/link_scan.dart';
import 'engine/model.dart';
import 'engine/text_scan.dart';
import 'native.dart';
import 'screens/batch_screen.dart';
import 'screens/result_screen.dart';
import 'theme.dart';
import 'widgets.dart';

const maxFileBytes = 100 << 20;

ScanResult _fileJob((String, Uint8List) a) => checkFile(a.$1, a.$2);
ScanResult _linkJob(String v) => checkLink(v);
ScanResult _textJob(String v) => checkText(v);

Future<void> _run(BuildContext context, AppState app, Future<ScanResult> Function() job) async {
  final nav = Navigator.of(context);
  showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (_) => PopScope(
      canPop: false,
      child: Center(
        child: Container(
          padding: const EdgeInsets.all(24),
          decoration: BoxDecoration(color: C.surface, borderRadius: BorderRadius.circular(22), border: Border.all(color: C.line)),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            const SizedBox(width: 44, height: 44, child: CircularProgressIndicator(strokeWidth: 3, color: C.cyan)),
            const SizedBox(height: 14),
            Text(app.s.checking, style: const TextStyle(color: C.ink, fontSize: 15, decoration: TextDecoration.none, fontWeight: FontWeight.w600)),
          ]),
        ),
      ),
    ),
  );
  try {
    final r = await job();
    app.add(r);
    app.buzz(r.verdict);
    updateWidget(app, r);
    nav.pop();
    await nav.push(MaterialPageRoute(builder: (_) => ResultScreen(result: r)));
  } catch (_) {
    nav.pop();
    if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(app.s.readFailed)));
  }
}

Future<void> pickAndCheckFile(BuildContext context, AppState app) async {
  final f = await FilePicker.pickFile();
  if (f == null || !context.mounted) return;
  final size = f.lengthSync() ?? await f.length() ?? 0;
  if (!context.mounted) return;
  if (size > maxFileBytes) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(app.s.tooBig)));
    return;
  }
  Uint8List bytes;
  try {
    bytes = await f.readAsBytes();
  } catch (_) {
    if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(app.s.readFailed)));
    return;
  }
  if (!context.mounted) return;
  await _run(context, app, () => compute(_fileJob, (f.name, bytes)));
}

Future<void> checkLinkValue(BuildContext context, AppState app, String value) => _run(context, app, () => compute(_linkJob, value));
Future<void> checkTextValue(BuildContext context, AppState app, String value) => _run(context, app, () => compute(_textJob, value));

/// Sends the latest result to the home-screen widget (Android; a no-op elsewhere).
void updateWidget(AppState app, ScanResult? r) {
  final s = app.s;
  Native.updateWidget(
    verdict: r?.verdict.name ?? '',
    label: r == null ? '' : s.verdict(r.verdict.name),
    target: r?.target ?? '',
    score: r?.score ?? 0,
    when: r == null ? '' : agoText(r.when, app.ar),
    button: s.quickScan,
    empty: s.widgetEmpty,
  );
}

final _linkLike = RegExp(r'^(?:https?://|www\.)\S+$|^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/\S*)?$', caseSensitive: false);

/// Text shared from another app: a lone link is checked as a link, anything longer as a message.
Future<void> checkSharedText(BuildContext context, AppState app, String text) {
  final t = text.trim();
  if (t.isEmpty) return Future.value();
  return _linkLike.hasMatch(t) ? checkLinkValue(context, app, t) : checkTextValue(context, app, t);
}

/// Files shared from another app (already copied to the app's cache by MainActivity).
/// One file opens its result; several are checked one after another and listed together.
Future<void> checkSharedFiles(BuildContext context, AppState app, List<SharedFile> files, {int skipped = 0}) async {
  final readable = files.where((f) => f.path != null && !f.tooBig).toList();
  final missed = skipped + files.length - readable.length;
  final messenger = ScaffoldMessenger.of(context);
  if (missed > 0) messenger.showSnackBar(SnackBar(content: Text(app.s.sharedSkipped(missed))));
  if (readable.isEmpty) return;
  if (readable.length == 1) {
    final f = readable.first;
    final Uint8List bytes;
    try {
      bytes = await File(f.path!).readAsBytes();
    } catch (_) {
      messenger.showSnackBar(SnackBar(content: Text(app.s.readFailed)));
      return;
    }
    if (!context.mounted) return;
    await _run(context, app, () => compute(_fileJob, (f.name, bytes)));
  } else {
    final nav = Navigator.of(context);
    final results = <ScanResult>[];
    final progress = ValueNotifier<int>(0);
    showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => PopScope(
        canPop: false,
        child: AlertDialog(
          content: ValueListenableBuilder<int>(
            valueListenable: progress,
            builder: (_, i, _) => Row(children: [
              const SizedBox(width: 28, height: 28, child: CircularProgressIndicator(strokeWidth: 3, color: C.cyan)),
              const SizedBox(width: 16),
              Expanded(child: Text('${app.s.checking} ${i + 1}/${readable.length}')),
            ]),
          ),
        ),
      ),
    );
    for (final (i, f) in readable.indexed) {
      progress.value = i;
      try {
        final bytes = await File(f.path!).readAsBytes();
        final r = await compute(_fileJob, (f.name, bytes));
        app.add(r);
        results.add(r);
      } catch (_) {}
    }
    nav.pop();
    progress.dispose();
    if (results.isEmpty) return;
    results.sort((a, b) => b.score.compareTo(a.score));
    app.buzz(results.first.verdict);
    updateWidget(app, results.first);
    await nav.push(MaterialPageRoute(builder: (_) => BatchScreen(results: results)));
  }
  Native.clearShared();
}

/// Files from the watched folder: copied through the Storage Access Framework, then checked.
Future<void> checkFolderFiles(BuildContext context, AppState app, List<FolderFile> files) async {
  final copies = <SharedFile>[];
  for (final f in files) {
    final c = await Native.copyDocument(f.uri);
    copies.add(c ?? SharedFile(f.name, null, f.size, false));
  }
  app.markFolderSeen();
  if (!context.mounted) return;
  await checkSharedFiles(context, app, copies);
}
