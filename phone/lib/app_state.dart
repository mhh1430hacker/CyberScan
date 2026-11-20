// Settings and history, kept on the phone (shared preferences). Nothing leaves the device.
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'engine/model.dart';
import 'strings.dart';

class AppState extends ChangeNotifier {
  static const _kLang = 'lang', _kHaptics = 'haptics', _kKeep = 'keepHistory', _kHistory = 'history', _kIntro = 'introDone';
  static const maxHistory = 100;
  SharedPreferences? _prefs;
  String lang = 'en';
  bool haptics = true, keepHistory = true, introDone = false, langChosen = false;
  List<ScanResult> history = [];

  bool get ar => lang == 'ar';
  S get s => S(ar);

  Future<void> load() async {
    final p = _prefs = await SharedPreferences.getInstance();
    langChosen = p.containsKey(_kLang);
    lang = p.getString(_kLang) ?? (PlatformDispatcher.instance.locale.languageCode == 'ar' ? 'ar' : 'en');
    haptics = p.getBool(_kHaptics) ?? true;
    keepHistory = p.getBool(_kKeep) ?? true;
    introDone = p.getBool(_kIntro) ?? false;
    try {
      history = (jsonDecode(p.getString(_kHistory) ?? '[]') as List)
          .map((e) => ScanResult.fromJson(Map<String, dynamic>.from(e as Map)))
          .toList();
    } catch (_) {
      history = [];
    }
    notifyListeners();
  }

  void setLang(String l) { lang = l; langChosen = true; _prefs?.setString(_kLang, l); notifyListeners(); }
  void setHaptics(bool v) { haptics = v; _prefs?.setBool(_kHaptics, v); notifyListeners(); }
  void setKeepHistory(bool v) { keepHistory = v; _prefs?.setBool(_kKeep, v); notifyListeners(); }
  void finishIntro() { introDone = true; _prefs?.setBool(_kIntro, true); notifyListeners(); }

  void add(ScanResult r) {
    if (!keepHistory) return;
    history = [r, ...history].take(maxHistory).toList();
    _save();
  }

  void removeAt(ScanResult r) { history = history.where((x) => !identical(x, r)).toList(); _save(); }
  void clearHistory() { history = []; _save(); }
  void _save() { _prefs?.setString(_kHistory, jsonEncode(history.map((r) => r.toJson()).toList())); notifyListeners(); }

  void buzz(Verdict v) {
    if (!haptics) return;
    switch (v) {
      case Verdict.suspicious: HapticFeedback.heavyImpact();
      case Verdict.review: HapticFeedback.mediumImpact();
      case Verdict.clear: HapticFeedback.lightImpact();
    }
  }

  int get warningCount => history.where((r) => r.verdict == Verdict.suspicious).length;
}
