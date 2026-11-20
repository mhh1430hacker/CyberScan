// Settings: language, vibration, history, privacy and about.
import 'package:flutter/material.dart';

import '../main.dart';
import '../theme.dart';
import '../widgets.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});
  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    Widget group(List<Widget> rows) => Container(
          decoration: BoxDecoration(color: C.surface, borderRadius: BorderRadius.circular(18), border: Border.all(color: C.line)),
          child: Column(children: [for (final (i, r) in rows.indexed) ...[if (i > 0) const Divider(indent: 16, endIndent: 16), r]]),
        );
    return SafeArea(
      bottom: false,
      child: ListView(padding: const EdgeInsets.fromLTRB(16, 8, 16, 24), children: [
        Text(s.navSettings, style: const TextStyle(fontSize: 30, fontWeight: FontWeight.w800)),
        SectionTitle(s.language),
        group([
          Padding(
            padding: const EdgeInsets.all(12),
            child: SegmentedButton<String>(
              segments: const [ButtonSegment(value: 'en', label: Text('English')), ButtonSegment(value: 'ar', label: Text('العربية'))],
              selected: {app.lang},
              onSelectionChanged: (v) => app.setLang(v.first),
              style: SegmentedButton.styleFrom(selectedBackgroundColor: C.cyan.withValues(alpha: .18), selectedForegroundColor: C.cyan, side: const BorderSide(color: C.line)),
            ),
          ),
        ]),
        SectionTitle(s.general),
        group([
          SwitchListTile(value: app.haptics, onChanged: app.setHaptics, title: Text(s.haptics), subtitle: Text(s.hapticsSub, style: const TextStyle(color: C.muted))),
          SwitchListTile(value: app.keepHistory, onChanged: app.setKeepHistory, title: Text(s.keepHistory), subtitle: Text(s.keepHistorySub, style: const TextStyle(color: C.muted))),
        ]),
        SectionTitle(s.privacy),
        group([Padding(padding: const EdgeInsets.all(16), child: Text(s.privacyText, style: const TextStyle(height: 1.55)))]),
        SectionTitle(s.about),
        group([
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(s.aboutText, style: const TextStyle(height: 1.5)),
              const SizedBox(height: 10),
              Text(s.engineLine, style: const TextStyle(color: C.muted, fontSize: 13, height: 1.5)),
              const SizedBox(height: 10),
              Text('${s.version} 2.0.0', style: const TextStyle(color: C.muted, fontSize: 13)),
            ]),
          ),
        ]),
      ]),
    );
  }
}
