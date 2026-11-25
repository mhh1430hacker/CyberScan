// Home: what CyberScan does, the four ways to check, the numbers and the latest checks.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../checks.dart';
import '../engine/model.dart';
import '../main.dart';
import '../theme.dart';
import '../widgets.dart';
import 'qr_screen.dart';
import 'result_screen.dart';

class HomeScreen extends StatelessWidget {
  final VoidCallback onSeeAll;
  const HomeScreen({super.key, required this.onSeeAll});

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    final recent = app.history.take(3).toList();
    return SafeArea(
      bottom: false,
      child: ListView(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
        children: [
          Row(children: [
            const _Logo(),
            const SizedBox(width: 10),
            Text(s.appName, style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 20, letterSpacing: .3)),
          ]),
          const SizedBox(height: 22),
          ShaderMask(
            shaderCallback: (r) => C.brand.createShader(r),
            child: Text(s.greeting, style: const TextStyle(fontSize: 30, fontWeight: FontWeight.w800, height: 1.15, color: Colors.white)),
          ),
          const SizedBox(height: 8),
          Row(children: [
            const Icon(Icons.lock_outline_rounded, size: 16, color: C.ok),
            const SizedBox(width: 6),
            Expanded(child: Text(s.onDevice, style: const TextStyle(color: C.muted, fontSize: 13.5))),
          ]),
          const SizedBox(height: 18),
          GridView.count(
            crossAxisCount: 2,
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            mainAxisSpacing: 12,
            crossAxisSpacing: 12,
            childAspectRatio: .98,
            children: [
              ActionCard(icon: Icons.description_outlined, title: s.checkFile, subtitle: s.checkFileSub, onTap: () => pickAndCheckFile(context, app)),
              ActionCard(icon: Icons.link_rounded, title: s.checkLink, subtitle: s.checkLinkSub, tint: C.violet,
                  onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const InputScreen(link: true)))),
              ActionCard(icon: Icons.sms_outlined, title: s.checkText, subtitle: s.checkTextSub, tint: C.violet,
                  onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const InputScreen(link: false)))),
              ActionCard(icon: Icons.qr_code_scanner_rounded, title: s.scanQr, subtitle: s.scanQrSub,
                  onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const QrScreen()))),
            ],
          ),
          if (app.newFiles.isNotEmpty) ...[
            const SizedBox(height: 14),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(color: C.surface, borderRadius: BorderRadius.circular(18), border: Border.all(color: C.cyan.withValues(alpha: .45))),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  const Icon(Icons.download_rounded, color: C.cyan),
                  const SizedBox(width: 8),
                  Expanded(child: Text(s.newFilesCount(app.newFiles.length, app.watchFolder ?? ''), style: const TextStyle(fontWeight: FontWeight.w700))),
                ]),
                const SizedBox(height: 6),
                Text(app.newFiles.take(3).map((f) => f.name).join(' · '), maxLines: 2, overflow: TextOverflow.ellipsis, style: const TextStyle(color: C.muted, fontSize: 13)),
                const SizedBox(height: 8),
                Row(mainAxisAlignment: MainAxisAlignment.end, children: [
                  TextButton(onPressed: app.markFolderSeen, child: Text(s.dismiss)),
                  const SizedBox(width: 6),
                  FilledButton(
                    onPressed: () => checkFolderFiles(context, app, app.newFiles),
                    style: FilledButton.styleFrom(backgroundColor: C.cyan, foregroundColor: C.bg),
                    child: Text(s.scanThem),
                  ),
                ]),
              ]),
            ),
          ],
          if (app.history.isEmpty) ...[
            const SizedBox(height: 16),
            Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Icon(Icons.ios_share_rounded, size: 18, color: C.violet),
              const SizedBox(width: 8),
              Expanded(child: Text(s.shareTip, style: const TextStyle(color: C.muted, fontSize: 13, height: 1.45))),
            ]),
          ],
          if (app.history.isNotEmpty) ...[
            const SizedBox(height: 18),
            Row(children: [
              _Stat('${app.history.length}', s.checks, C.ink),
              const SizedBox(width: 10),
              _Stat('${app.warningCount}', s.warnings, app.warningCount > 0 ? C.bad : C.ink),
              const SizedBox(width: 10),
              _Stat(agoText(app.history.first.when, app.ar), s.lastCheck, C.ink, small: true),
            ]),
            SectionTitle(s.recent, trailing: TextButton(onPressed: onSeeAll, child: Text(s.seeAll))),
            for (final r in recent) ...[HistoryRow(result: r), const SizedBox(height: 8)],
          ],
        ],
      ),
    );
  }
}

class _Logo extends StatelessWidget {
  const _Logo();
  @override
  Widget build(BuildContext context) => Container(
        width: 36,
        height: 36,
        decoration: BoxDecoration(borderRadius: BorderRadius.circular(11), gradient: const LinearGradient(colors: [C.cyan, C.violet])),
        child: const Icon(Icons.shield_outlined, color: C.bg, size: 22),
      );
}

class _Stat extends StatelessWidget {
  final String value, label;
  final Color color;
  final bool small;
  const _Stat(this.value, this.label, this.color, {this.small = false});
  @override
  Widget build(BuildContext context) => Expanded(
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 6),
          decoration: BoxDecoration(color: C.surface, borderRadius: BorderRadius.circular(16), border: Border.all(color: C.line)),
          child: Column(children: [
            Text(value, maxLines: 1, overflow: TextOverflow.ellipsis, style: TextStyle(fontSize: small ? 15 : 22, fontWeight: FontWeight.w800, color: color)),
            const SizedBox(height: 2),
            Text(label, style: const TextStyle(color: C.muted, fontSize: 12)),
          ]),
        ),
      );
}

/// A saved check, as shown on Home and in History.
class HistoryRow extends StatelessWidget {
  final ScanResult result;
  final VoidCallback? onDelete;
  const HistoryRow({super.key, required this.result, this.onDelete});
  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final color = C.verdict(result.verdict);
    final icon = switch (result.kind) { CheckKind.file => Icons.description_outlined, CheckKind.link => Icons.link_rounded, CheckKind.text => Icons.sms_outlined };
    return Material(
      color: C.surface,
      borderRadius: BorderRadius.circular(16),
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => ResultScreen(result: result))),
        child: Container(
          padding: const EdgeInsets.fromLTRB(12, 10, 8, 10),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(16), border: Border.all(color: C.line)),
          child: Row(children: [
            Container(
              width: 40, height: 40,
              decoration: BoxDecoration(color: color.withValues(alpha: .13), borderRadius: BorderRadius.circular(12)),
              child: Icon(icon, color: color, size: 21),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(result.target, maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(fontWeight: FontWeight.w600)),
                const SizedBox(height: 2),
                Text('${app.s.verdict(result.verdict.name)} · ${result.score}/100 · ${agoText(result.when, app.ar)}', style: TextStyle(color: color, fontSize: 12.5)),
              ]),
            ),
            if (onDelete != null) IconButton(onPressed: onDelete, icon: const Icon(Icons.close_rounded, color: C.muted, size: 20), tooltip: app.s.remove),
          ]),
        ),
      ),
    );
  }
}

/// Typing or pasting a link or a message.
class InputScreen extends StatefulWidget {
  final bool link;
  final String? initial;
  const InputScreen({super.key, required this.link, this.initial});
  @override
  State<InputScreen> createState() => _InputScreenState();
}

class _InputScreenState extends State<InputScreen> {
  late final TextEditingController _c = TextEditingController(text: widget.initial ?? '');
  @override
  void dispose() { _c.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    return Scaffold(
      appBar: AppBar(title: Text(widget.link ? s.checkLink : s.checkText)),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
          child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            TextField(
              controller: _c,
              autofocus: widget.initial == null,
              minLines: widget.link ? 1 : 6,
              maxLines: widget.link ? 3 : 12,
              keyboardType: widget.link ? TextInputType.url : TextInputType.multiline,
              textDirection: widget.link ? TextDirection.ltr : null,
              decoration: InputDecoration(hintText: widget.link ? s.linkHint : s.textHint),
              onChanged: (_) => setState(() {}),
            ),
            const SizedBox(height: 10),
            Align(
              alignment: AlignmentDirectional.centerStart,
              child: TextButton.icon(
                onPressed: () async {
                  final data = await Clipboard.getData(Clipboard.kTextPlain);
                  if (data?.text != null) setState(() => _c.text = data!.text!.trim());
                },
                icon: const Icon(Icons.content_paste_rounded),
                label: Text(s.paste),
              ),
            ),
            const Spacer(),
            FilledButton(
              onPressed: _c.text.trim().length < 3
                  ? null
                  : () => widget.link ? checkLinkValue(context, app, _c.text.trim()) : checkTextValue(context, app, _c.text.trim()),
              style: FilledButton.styleFrom(padding: const EdgeInsets.symmetric(vertical: 16), backgroundColor: C.cyan, foregroundColor: C.bg,
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16))),
              child: Text(s.check, style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 16)),
            ),
          ]),
        ),
      ),
    );
  }
}
