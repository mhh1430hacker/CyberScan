// Runs a check off the interface thread (an isolate), saves it and opens the result.
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'app_state.dart';
import 'engine/file_scan.dart';
import 'engine/link_scan.dart';
import 'engine/model.dart';
import 'engine/text_scan.dart';
import 'screens/result_screen.dart';
import 'theme.dart';

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
