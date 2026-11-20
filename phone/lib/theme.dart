// CyberScan's identity on the phone: violet-black, cyan and violet light, colour only for meaning.
import 'package:flutter/material.dart';

import 'engine/model.dart';

class C {
  static const bg = Color(0xFF07051A);
  static const surface = Color(0xFF120D2C);
  static const surface2 = Color(0xFF1C1540);
  static const line = Color(0x29B4A0FF);
  static const ink = Color(0xFFF3EEFF);
  static const muted = Color(0xFFA99DC9);
  static const cyan = Color(0xFF22E8FF);
  static const violet = Color(0xFFB46CFF);
  static const pink = Color(0xFFFF4FD8);
  static const ok = Color(0xFF3DFFB0);
  static const warn = Color(0xFFFFC84A);
  static const bad = Color(0xFFFF4F6D);

  static Color verdict(Verdict v) => switch (v) { Verdict.clear => ok, Verdict.review => warn, Verdict.suspicious => bad };
  static Color severity(Severity s) => switch (s) {
        Severity.critical || Severity.high => bad,
        Severity.medium => warn,
        Severity.low => const Color(0xFF7DB4FF),
        Severity.info => muted,
      };
  static const brand = LinearGradient(colors: [cyan, violet, pink], begin: Alignment.centerLeft, end: Alignment.centerRight);
}

ThemeData buildTheme(bool ar) {
  final base = ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    scaffoldBackgroundColor: C.bg,
    colorScheme: const ColorScheme.dark(primary: C.cyan, secondary: C.violet, surface: C.surface, error: C.bad, onPrimary: Color(0xFF04121B)),
    fontFamily: ar ? 'Roboto' : null,
  );
  return base.copyWith(
    textTheme: base.textTheme.apply(bodyColor: C.ink, displayColor: C.ink),
    appBarTheme: const AppBarTheme(backgroundColor: Colors.transparent, elevation: 0, scrolledUnderElevation: 0, centerTitle: false),
    cardTheme: CardThemeData(color: C.surface, elevation: 0, margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20), side: const BorderSide(color: C.line))),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: const Color(0xEE0A0720),
      indicatorColor: C.cyan.withValues(alpha: .16),
      labelTextStyle: WidgetStateProperty.resolveWith((s) => TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: s.contains(WidgetState.selected) ? C.cyan : C.muted)),
      iconTheme: WidgetStateProperty.resolveWith((s) => IconThemeData(color: s.contains(WidgetState.selected) ? C.cyan : C.muted)),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true, fillColor: C.surface2,
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: const BorderSide(color: C.line)),
      enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: const BorderSide(color: C.line)),
      focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: const BorderSide(color: C.cyan, width: 1.5)),
      hintStyle: const TextStyle(color: C.muted),
    ),
    switchTheme: SwitchThemeData(thumbColor: WidgetStateProperty.resolveWith((s) => s.contains(WidgetState.selected) ? C.bg : C.muted),
        trackColor: WidgetStateProperty.resolveWith((s) => s.contains(WidgetState.selected) ? C.cyan : C.surface2)),
    snackBarTheme: const SnackBarThemeData(backgroundColor: C.surface2, contentTextStyle: TextStyle(color: C.ink), behavior: SnackBarBehavior.floating),
    dividerTheme: const DividerThemeData(color: C.line, space: 1),
  );
}
