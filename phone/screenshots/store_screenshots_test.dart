// Store screenshots of the real app screens (Google Play, 1080x1920), in English and Arabic.
//
//   cd phone
//   flutter test screenshots/store_screenshots_test.dart
//
// Output: phone/screenshots/out/<lang>_<n>_<screen>.png. Kept out of test/ so the normal
// `flutter test` run doesn't need the fonts. Real fonts are loaded (Roboto and the Material
// icons from the Flutter SDK, Noto Sans Arabic from Windows) so text renders as on a phone.
// The scan results shown are produced by the real on-phone engine from synthetic samples.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:cyberscan/app_state.dart';
import 'package:cyberscan/engine/file_scan.dart';
import 'package:cyberscan/engine/link_scan.dart';
import 'package:cyberscan/engine/model.dart';
import 'package:cyberscan/engine/text_scan.dart';
import 'package:cyberscan/main.dart';
import 'package:cyberscan/screens/result_screen.dart';
import 'package:cyberscan/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

const flutterFonts = r'C:\Users\mahdi\flutter\bin\cache\artifacts\material_fonts';

Future<void> loadFont(String family, List<String> files) async {
  final loader = FontLoader(family);
  for (final f in files) {
    if (File(f).existsSync()) loader.addFont(Future.value(ByteData.sublistView(File(f).readAsBytesSync())));
  }
  await loader.load();
}

Uint8List fakeInvoiceExe() {
  final b = BytesBuilder();
  final dos = Uint8List(0x80);
  dos[0] = 0x4D; dos[1] = 0x5A; dos[0x3C] = 0x80;
  b.add(dos);
  final pe = Uint8List(24 + 0xE0 + 40);
  pe.setAll(0, [0x50, 0x45, 0, 0]);
  pe[6] = 1; pe[20] = 0xE0;
  final sec = 24 + 0xE0;
  pe.setAll(sec, ascii.encode('.text'));
  final d = pe.buffer.asByteData();
  d.setUint32(sec + 16, 512, Endian.little);
  d.setUint32(sec + 20, 0x80 + pe.length, Endian.little);
  d.setUint32(sec + 36, 0x60000020, Endian.little);
  b.add(pe);
  b.add(Uint8List(512));
  b.add(ascii.encode('powershell -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA== VirtualAlloc WriteProcessMemory CreateRemoteThread'));
  return b.toBytes();
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUpAll(() async {
    await loadFont('Roboto', ['regular', 'medium', 'bold', 'black'].map((w) => '$flutterFonts\\roboto-$w.ttf').toList());
    await loadFont('MaterialIcons', ['$flutterFonts\\materialicons-regular.otf']);
    await loadFont('monospace', [r'C:\Windows\Fonts\consola.ttf']); // Android's monospace stand-in
    await loadFont('NotoSansArabic', [r'C:\Windows\Fonts\NotoSansArabic-Regular.ttf', r'C:\Windows\Fonts\NotoSansArabic-Bold.ttf']);
  });

  final now = DateTime.now();
  ScanResult at(ScanResult r, Duration ago) => ScanResult.fromJson({...r.toJson(), 'when': now.subtract(ago).toIso8601String()});
  List<ScanResult> sampleHistory() => [
        at(checkLink('https://paypa1-login.verify-account.xyz/signin'), const Duration(minutes: 2)),
        at(checkFile('invoice.pdf.exe', fakeInvoiceExe()), const Duration(minutes: 9)),
        at(checkText('Your parcel is on hold. Pay the 2 SAR customs fee within 24 hours: http://bit.ly/x9-parcel or it will be returned.'), const Duration(hours: 1)),
        at(checkFile('holiday-photo.jpg', Uint8List.fromList([0xFF, 0xD8, 0xFF, 0xE0, ...List.filled(2000, 7), 0xFF, 0xD9])), const Duration(hours: 3)),
        at(checkLink('https://www.wikipedia.org/'), const Duration(days: 1)),
      ];

  Future<void> shoot(WidgetTester tester, String lang, String name, Widget Function(AppState) screen, {bool tab = false}) async {
    tester.view.physicalSize = const Size(1080, 1920);
    tester.view.devicePixelRatio = 2.625;
    addTearDown(tester.view.reset);
    final history = sampleHistory();
    // ignore: invalid_use_of_visible_for_testing_member
    SharedPreferences.setMockInitialValues({
      'lang': lang, 'introDone': true,
      'history': jsonEncode(history.map((r) => r.toJson()).toList()),
    });
    final app = AppState();
    await app.load();
    final theme = buildTheme(lang == 'ar');
    final key = GlobalKey();
    await tester.pumpWidget(RepaintBoundary(
      key: key,
      child: AppScope(
        notifier: app,
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: theme.copyWith(
            textTheme: theme.textTheme.apply(fontFamily: 'Roboto', fontFamilyFallback: const ['NotoSansArabic']),
          ),
          locale: Locale(lang),
          supportedLocales: const [Locale('en'), Locale('ar')],
          localizationsDelegates: const [GlobalMaterialLocalizations.delegate, GlobalWidgetsLocalizations.delegate, GlobalCupertinoLocalizations.delegate],
          home: screen(app),
        ),
      ),
    ));
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pump(const Duration(seconds: 2));
    // full resolution (1080x1920): render the boundary at the device pixel ratio and save it
    final boundary = key.currentContext!.findRenderObject()! as RenderRepaintBoundary;
    await tester.runAsync(() async {
      final image = await boundary.toImage(pixelRatio: 2.625);
      final png = await image.toByteData(format: ui.ImageByteFormat.png);
      final out = File('screenshots/out/${lang}_$name.png')..parent.createSync(recursive: true);
      out.writeAsBytesSync(png!.buffer.asUint8List());
    });
  }

  for (final lang in ['en', 'ar']) {
    testWidgets('$lang home', (t) => shoot(t, lang, '1_home', (_) => const Shell()));
    testWidgets('$lang link result', (t) => shoot(t, lang, '2_link_result', (a) => ResultScreen(result: a.history[0])));
    testWidgets('$lang file result', (t) => shoot(t, lang, '3_file_result', (a) => ResultScreen(result: a.history[1])));
    testWidgets('$lang message result', (t) => shoot(t, lang, '4_message_result', (a) => ResultScreen(result: a.history[2])));
    testWidgets('$lang history', (t) => shoot(t, lang, '5_history', (_) => const _Tab(1)));
    testWidgets('$lang tools', (t) => shoot(t, lang, '6_tools', (_) => const _Tab(2)));
  }
}

/// The app shell opened on another tab.
class _Tab extends StatelessWidget {
  final int index;
  const _Tab(this.index);
  @override
  Widget build(BuildContext context) => _ShellAt(index: index);
}

class _ShellAt extends StatefulWidget {
  final int index;
  const _ShellAt({required this.index});
  @override
  State<_ShellAt> createState() => _ShellAtState();
}

class _ShellAtState extends State<_ShellAt> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final bar = find.byType(NavigationDestination).evaluate().elementAt(widget.index);
      final nav = bar.findAncestorWidgetOfExactType<NavigationBar>();
      nav?.onDestinationSelected?.call(widget.index);
    });
  }

  @override
  Widget build(BuildContext context) => const Shell();
}
