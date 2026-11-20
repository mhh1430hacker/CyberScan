// CyberScan for phones: check files, links and messages on the device.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import 'app_state.dart';
import 'screens/history_screen.dart';
import 'screens/home_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/tools_screen.dart';
import 'theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(statusBarColor: Colors.transparent, systemNavigationBarColor: C.bg));
  final app = AppState();
  await app.load();
  runApp(AppScope(notifier: app, child: const CyberScanApp()));
}

/// Gives every screen the app state, and rebuilds them when it changes.
class AppScope extends InheritedNotifier<AppState> {
  const AppScope({super.key, required AppState super.notifier, required super.child});
  static AppState of(BuildContext context) => context.dependOnInheritedWidgetOfExactType<AppScope>()!.notifier!;
}

class CyberScanApp extends StatelessWidget {
  const CyberScanApp({super.key});
  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    return MaterialApp(
      title: 'CyberScan',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(app.ar),
      locale: Locale(app.lang),
      supportedLocales: const [Locale('en'), Locale('ar')],
      localizationsDelegates: const [GlobalMaterialLocalizations.delegate, GlobalWidgetsLocalizations.delegate, GlobalCupertinoLocalizations.delegate],
      home: !app.langChosen ? const LanguageScreen() : !app.introDone ? const IntroScreen() : const Shell(),
    );
  }
}

class Shell extends StatefulWidget {
  const Shell({super.key});
  @override
  State<Shell> createState() => _ShellState();
}

class _ShellState extends State<Shell> {
  int _tab = 0;
  @override
  Widget build(BuildContext context) {
    final s = AppScope.of(context).s;
    final pages = [HomeScreen(onSeeAll: () => setState(() => _tab = 1)), const HistoryScreen(), const ToolsScreen(), const SettingsScreen()];
    return Scaffold(
      body: DecoratedBox(
        decoration: const BoxDecoration(
          gradient: RadialGradient(center: Alignment(-.9, -1.1), radius: 1.3, colors: [Color(0x332B1B6B), C.bg]),
        ),
        child: IndexedStack(index: _tab, children: pages),
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) { HapticFeedback.selectionClick(); setState(() => _tab = i); },
        destinations: [
          NavigationDestination(icon: const Icon(Icons.shield_outlined), selectedIcon: const Icon(Icons.shield_rounded), label: s.navHome),
          NavigationDestination(icon: const Icon(Icons.history_rounded), label: s.navHistory),
          NavigationDestination(icon: const Icon(Icons.grid_view_outlined), selectedIcon: const Icon(Icons.grid_view_rounded), label: s.navTools),
          NavigationDestination(icon: const Icon(Icons.settings_outlined), selectedIcon: const Icon(Icons.settings_rounded), label: s.navSettings),
        ],
      ),
    );
  }
}

/// First launch: the language, asked once.
class LanguageScreen extends StatelessWidget {
  const LanguageScreen({super.key});
  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    Widget choice(String code, String title, String sub) => Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: Material(
            color: C.surface,
            borderRadius: BorderRadius.circular(18),
            child: InkWell(
              borderRadius: BorderRadius.circular(18),
              onTap: () => app.setLang(code),
              child: Container(
                width: double.infinity,
                padding: const EdgeInsets.all(18),
                decoration: BoxDecoration(borderRadius: BorderRadius.circular(18), border: Border.all(color: C.cyan.withValues(alpha: .35))),
                child: Column(crossAxisAlignment: code == 'ar' ? CrossAxisAlignment.end : CrossAxisAlignment.start, children: [
                  Text(title, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
                  Text(sub, style: const TextStyle(color: C.muted)),
                ]),
              ),
            ),
          ),
        );
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
            Container(
              width: 84, height: 84,
              decoration: BoxDecoration(borderRadius: BorderRadius.circular(26), gradient: const LinearGradient(colors: [C.cyan, C.violet]),
                  boxShadow: [BoxShadow(color: C.cyan.withValues(alpha: .4), blurRadius: 30)]),
              child: const Icon(Icons.shield_outlined, color: C.bg, size: 48),
            ),
            const SizedBox(height: 24),
            const Text('Choose your language', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w700)),
            const Text('اختر لغتك', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w700)),
            const SizedBox(height: 28),
            choice('en', 'English', 'Continue in English'),
            choice('ar', 'العربية', 'المتابعة بالعربية'),
          ]),
        ),
      ),
    );
  }
}

/// First launch: three short cards about what CyberScan does.
class IntroScreen extends StatefulWidget {
  const IntroScreen({super.key});
  @override
  State<IntroScreen> createState() => _IntroScreenState();
}

class _IntroScreenState extends State<IntroScreen> {
  final _page = PageController();
  int _i = 0;
  static const _icons = [Icons.search_rounded, Icons.phone_iphone_rounded, Icons.handyman_rounded];

  @override
  void dispose() { _page.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    final cards = s.intro;
    return Scaffold(
      body: SafeArea(
        child: Column(children: [
          Align(alignment: AlignmentDirectional.centerEnd, child: TextButton(onPressed: app.finishIntro, child: Text(s.skip))),
          Expanded(
            child: PageView.builder(
              controller: _page,
              itemCount: cards.length,
              onPageChanged: (i) => setState(() => _i = i),
              itemBuilder: (_, i) => Padding(
                padding: const EdgeInsets.all(28),
                child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
                  Container(
                    width: 140, height: 140,
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(40),
                      gradient: RadialGradient(colors: [(i.isEven ? C.cyan : C.violet).withValues(alpha: .35), C.surface2]),
                      border: Border.all(color: C.line),
                    ),
                    child: Icon(_icons[i], size: 64, color: i.isEven ? C.cyan : C.violet),
                  ),
                  const SizedBox(height: 32),
                  Text(cards[i].$1, textAlign: TextAlign.center, style: const TextStyle(fontSize: 26, fontWeight: FontWeight.w800)),
                  const SizedBox(height: 12),
                  Text(cards[i].$2, textAlign: TextAlign.center, style: const TextStyle(color: C.muted, fontSize: 16, height: 1.55)),
                ]),
              ),
            ),
          ),
          Row(mainAxisAlignment: MainAxisAlignment.center, children: [
            for (var d = 0; d < cards.length; d++)
              AnimatedContainer(
                duration: const Duration(milliseconds: 250),
                margin: const EdgeInsets.symmetric(horizontal: 3),
                width: d == _i ? 22 : 8, height: 8,
                decoration: BoxDecoration(color: d == _i ? C.cyan : C.surface2, borderRadius: BorderRadius.circular(8)),
              ),
          ]),
          Padding(
            padding: const EdgeInsets.all(20),
            child: SizedBox(
              width: double.infinity,
              child: FilledButton(
                onPressed: () => _i < cards.length - 1 ? _page.nextPage(duration: const Duration(milliseconds: 320), curve: Curves.easeOutCubic) : app.finishIntro(),
                style: FilledButton.styleFrom(padding: const EdgeInsets.symmetric(vertical: 16), backgroundColor: C.cyan, foregroundColor: C.bg,
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16))),
                child: Text(_i < cards.length - 1 ? s.next : s.start, style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 16)),
              ),
            ),
          ),
        ]),
      ),
    );
  }
}
