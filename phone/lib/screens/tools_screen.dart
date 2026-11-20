// Tools: QR codes, verifying a download, password strength. All on the phone.
import 'dart:math' as math;

import 'package:crypto/crypto.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../main.dart';
import '../strings.dart';
import '../theme.dart';
import '../widgets.dart';
import 'home_screen.dart';
import 'qr_screen.dart';

class ToolsScreen extends StatelessWidget {
  const ToolsScreen({super.key});
  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    void open(Widget w) => Navigator.of(context).push(MaterialPageRoute(builder: (_) => w));
    return SafeArea(
      bottom: false,
      child: ListView(padding: const EdgeInsets.fromLTRB(16, 8, 16, 24), children: [
        Text(s.navTools, style: const TextStyle(fontSize: 30, fontWeight: FontWeight.w800)),
        const SizedBox(height: 6),
        Text(s.toolsLede, style: const TextStyle(color: C.muted)),
        const SizedBox(height: 16),
        GridView.count(
          crossAxisCount: 2, shrinkWrap: true, physics: const NeverScrollableScrollPhysics(),
          mainAxisSpacing: 12, crossAxisSpacing: 12, childAspectRatio: .98,
          children: [
            ActionCard(icon: Icons.qr_code_scanner_rounded, title: s.scanQr, subtitle: s.scanQrSub, onTap: () => open(const QrScreen())),
            ActionCard(icon: Icons.verified_outlined, title: s.verify, subtitle: s.verifySub, tint: C.violet, onTap: () => open(const VerifyScreen())),
            ActionCard(icon: Icons.password_rounded, title: s.password, subtitle: s.passwordSub, tint: C.violet, onTap: () => open(const PasswordScreen())),
            ActionCard(icon: Icons.sms_outlined, title: s.checkText, subtitle: s.checkTextSub, onTap: () => open(const InputScreen(link: false))),
          ],
        ),
      ]),
    );
  }
}

/// Verify a download: its fingerprint against the one the publisher lists.
class VerifyScreen extends StatefulWidget {
  const VerifyScreen({super.key});
  @override
  State<VerifyScreen> createState() => _VerifyScreenState();
}

class _VerifyScreenState extends State<VerifyScreen> {
  final _expected = TextEditingController();
  String? _name;
  Map<String, String> _sums = {};

  @override
  void dispose() { _expected.dispose(); super.dispose(); }

  Future<void> _pick() async {
    final f = await FilePicker.pickFile();
    if (f == null) return;
    final b = await f.readAsBytes();
    setState(() {
      _name = f.name;
      _sums = {'SHA-256': sha256.convert(b).toString(), 'SHA-1': sha1.convert(b).toString(), 'MD5': md5.convert(b).toString()};
    });
  }

  @override
  Widget build(BuildContext context) {
    final s = AppScope.of(context).s;
    final want = _expected.text.replaceAll(RegExp(r'[^0-9a-fA-F]'), '').toLowerCase();
    final hit = _sums.entries.where((e) => e.value == want).firstOrNull;
    return Scaffold(
      appBar: AppBar(title: Text(s.verify)),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        TextField(controller: _expected, textDirection: TextDirection.ltr, decoration: InputDecoration(hintText: s.verifyHint), onChanged: (_) => setState(() {})),
        const SizedBox(height: 12),
        OutlinedButton.icon(
          onPressed: _pick,
          icon: const Icon(Icons.folder_open_rounded),
          label: Text(_name ?? s.chooseFile, overflow: TextOverflow.ellipsis),
          style: OutlinedButton.styleFrom(padding: const EdgeInsets.symmetric(vertical: 16), side: const BorderSide(color: C.line), foregroundColor: C.ink),
        ),
        if (_sums.isNotEmpty && want.isNotEmpty) ...[
          const SizedBox(height: 14),
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: (hit != null ? C.ok : C.bad).withValues(alpha: .1),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: (hit != null ? C.ok : C.bad).withValues(alpha: .45)),
            ),
            child: Row(children: [
              Icon(hit != null ? Icons.check_circle_rounded : Icons.cancel_rounded, color: hit != null ? C.ok : C.bad),
              const SizedBox(width: 10),
              Expanded(child: Text(hit != null ? s.matchOk(hit.key) : s.matchBad, style: TextStyle(color: hit != null ? C.ok : C.bad, fontWeight: FontWeight.w600))),
            ]),
          ),
        ],
        for (final e in _sums.entries) ...[
          const SizedBox(height: 8),
          ListTile(
            tileColor: C.surface,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14), side: const BorderSide(color: C.line)),
            title: Text(e.key, style: const TextStyle(color: C.muted, fontSize: 12)),
            subtitle: Text(e.value, textDirection: TextDirection.ltr, style: const TextStyle(fontFamily: 'monospace', fontSize: 12.5, color: C.ink)),
            trailing: const Icon(Icons.copy_rounded, size: 18, color: C.muted),
            onTap: () {
              Clipboard.setData(ClipboardData(text: e.value));
              ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(s.copied), duration: const Duration(seconds: 1)));
            },
          ),
        ],
      ]),
    );
  }
}

/// Password strength, estimated on the phone. The password is never stored or sent.
class PasswordScreen extends StatefulWidget {
  const PasswordScreen({super.key});
  @override
  State<PasswordScreen> createState() => _PasswordScreenState();
}

const _common = ['password', '123456', '12345678', 'qwerty', 'abc123', '111111', '123123', 'admin', 'letmein', 'welcome', 'iloveyou', 'monkey', 'dragon',
  'football', 'princess', 'sunshine', 'passw0rd', 'master', 'login', '000000', '1q2w3e', 'qwertyuiop', 'asdfgh', 'zxcvbn', 'superman', 'trustno1'];

(int, double, List<String>) ratePassword(String pw, S s) {
  final tips = <String>[];
  var pool = 0;
  if (RegExp(r'[a-z]').hasMatch(pw)) pool += 26;
  if (RegExp(r'[A-Z]').hasMatch(pw)) pool += 26;
  if (RegExp(r'[0-9]').hasMatch(pw)) pool += 10;
  if (RegExp(r'[^A-Za-z0-9]').hasMatch(pw)) pool += 33;
  var bits = pw.isEmpty ? 0.0 : pw.length * math.log(math.max(pool, 1)) / math.ln2;
  final lower = pw.toLowerCase();
  if (_common.any(lower.contains)) { bits = math.min(bits, 12); tips.add(s.pwCommon); }
  if (RegExp(r'(.)\1{2,}').hasMatch(pw)) { bits -= 10; tips.add(s.pwRepeat); }
  if (RegExp(r'(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|qwer|asdf|zxcv)', caseSensitive: false).hasMatch(pw)) { bits -= 12; tips.add(s.pwSequence); }
  if (RegExp(r'(19|20)\d{2}').hasMatch(pw)) { bits -= 6; tips.add(s.pwYear); }
  if (pw.isNotEmpty && pw.length < 12) tips.add(s.pwLength);
  if (pw.isNotEmpty && pool < 60) tips.add(s.pwMix);
  bits = math.max(0, bits);
  final level = pw.isEmpty ? -1 : bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  return (level, bits, tips.toSet().take(3).toList());
}

class _PasswordScreenState extends State<PasswordScreen> {
  final _c = TextEditingController();
  bool _show = false;

  @override
  void dispose() { _c.clear(); _c.dispose(); super.dispose(); }

  String _time(double bits, S s, bool ar) {
    final secs = math.pow(2, bits) / 1e10 / 2;
    if (secs < 1) return s.pwInstant;
    if (secs > 31536000 * 1e6) return s.pwForever;
    final units = ar
        ? [(31536000.0, 'سنة'), (86400.0, 'يوم'), (3600.0, 'ساعة'), (60.0, 'دقيقة'), (1.0, 'ثانية')]
        : [(31536000.0, 'years'), (86400.0, 'days'), (3600.0, 'hours'), (60.0, 'minutes'), (1.0, 'seconds')];
    final (size, name) = units.firstWhere((u) => secs >= u.$1, orElse: () => units.last);
    return s.pwCrack('${(secs / size).round()} $name');
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    final (level, bits, tips) = ratePassword(_c.text, s);
    final colors = [C.bad, const Color(0xFFFF8A4F), C.warn, C.ok, C.ok];
    return Scaffold(
      appBar: AppBar(title: Text(s.password)),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        TextField(
          controller: _c,
          autofocus: true,
          obscureText: !_show,
          autocorrect: false,
          enableSuggestions: false,
          textDirection: TextDirection.ltr,
          decoration: InputDecoration(
            hintText: s.passwordHint,
            suffixIcon: IconButton(icon: Icon(_show ? Icons.visibility_off_rounded : Icons.visibility_rounded, color: C.muted), onPressed: () => setState(() => _show = !_show)),
          ),
          onChanged: (_) => setState(() {}),
        ),
        const SizedBox(height: 8),
        Text(s.pwPrivacy, style: const TextStyle(color: C.muted, fontSize: 12.5)),
        const SizedBox(height: 16),
        ClipRRect(
          borderRadius: BorderRadius.circular(8),
          child: LinearProgressIndicator(value: level < 0 ? 0 : (level + 1) / 5, minHeight: 10, backgroundColor: C.surface2, color: level < 0 ? C.surface2 : colors[level]),
        ),
        if (level >= 0) ...[
          const SizedBox(height: 12),
          Text(s.pwLevels[level], style: TextStyle(color: colors[level], fontWeight: FontWeight.w800, fontSize: 20)),
          const SizedBox(height: 4),
          Text(_time(bits, s, app.ar), style: const TextStyle(color: C.muted)),
          const SizedBox(height: 12),
          if (level < 3) for (final t in tips) Padding(padding: const EdgeInsets.only(bottom: 6), child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Padding(padding: EdgeInsets.only(top: 3), child: Icon(Icons.tips_and_updates_outlined, size: 16, color: C.warn)),
            const SizedBox(width: 8),
            Expanded(child: Text(t)),
          ])),
        ],
      ]),
    );
  }
}
