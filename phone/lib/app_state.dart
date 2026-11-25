// Settings and history, kept on the phone (shared preferences). Nothing leaves the device.
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'engine/model.dart';
import 'native.dart';
import 'strings.dart';

class AppState extends ChangeNotifier {
  static const _kLang = 'lang', _kHaptics = 'haptics', _kKeep = 'keepHistory', _kHistory = 'history', _kIntro = 'introDone';
  static const _kWatchSeen = 'watchSeen';
  static const maxHistory = 100;
  SharedPreferences? _prefs;
  String lang = 'en';
  bool haptics = true, keepHistory = true, introDone = false, langChosen = false;
  List<ScanResult> history = [];

  /// The watched folder (Android, Storage Access Framework): its name and the files added to it
  /// since the user last looked. Empty when no folder was granted.
  String? watchFolder;
  bool watchGranted = false;
  List<FolderFile> newFiles = [];

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

  /// Reads the watched folder and keeps the files modified after the last "seen" mark.
  Future<void> refreshFolder() async {
    final f = await Native.folder();
    watchFolder = f?['name'] as String?;
    watchGranted = f?['granted'] == true;
    if (watchFolder == null || !watchGranted) {
      newFiles = [];
      notifyListeners();
      return;
    }
    final seen = _prefs?.getInt(_kWatchSeen) ?? 0;
    final files = await Native.listFolder() ?? const <FolderFile>[];
    newFiles = files.where((x) => x.modified > seen).take(20).toList();
    notifyListeners();
  }

  Future<bool> chooseFolder() async {
    final f = await Native.pickFolder();
    if (f == null) return false;
    _prefs?.setInt(_kWatchSeen, DateTime.now().millisecondsSinceEpoch); // count files from now on
    await refreshFolder();
    return true;
  }

  Future<void> forgetFolder() async {
    await Native.forgetFolder();
    watchFolder = null;
    newFiles = [];
    notifyListeners();
  }

  void markFolderSeen() {
    _prefs?.setInt(_kWatchSeen, DateTime.now().millisecondsSinceEpoch);
    newFiles = [];
    notifyListeners();
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
