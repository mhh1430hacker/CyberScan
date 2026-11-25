// The Android side of Share to CyberScan, the home-screen widget and the watched folder
// (android/.../MainActivity.kt). Every call is safe on platforms without it (iOS, tests): it
// simply returns null / does nothing.
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Something handed to the app from outside: a share or the widget's Quick scan button.
class Incoming {
  final String type; // 'files' | 'text' | 'quickScan'
  final List<SharedFile> files;
  final String? text;
  final int skipped;
  const Incoming(this.type, {this.files = const [], this.text, this.skipped = 0});

  static Incoming? fromMap(Object? raw) {
    if (raw is! Map) return null;
    final m = Map<String, dynamic>.from(raw);
    final files = ((m['files'] as List?) ?? const [])
        .whereType<Map>()
        .map((f) => SharedFile(f['name']?.toString() ?? 'file', f['path'] as String?, (f['size'] as num?)?.toInt() ?? -1, f['tooBig'] == true))
        .toList();
    return Incoming(m['type']?.toString() ?? '', files: files, text: m['text'] as String?, skipped: (m['skipped'] as num?)?.toInt() ?? 0);
  }
}

class SharedFile {
  final String name;
  final String? path; // a private copy in the app's cache; null when too big or unreadable
  final int size;
  final bool tooBig;
  const SharedFile(this.name, this.path, this.size, this.tooBig);
}

/// A file in the watched folder.
class FolderFile {
  final String uri, name;
  final int size, modified; // modified: ms since epoch
  const FolderFile(this.uri, this.name, this.size, this.modified);
}

class Native {
  static const _ch = MethodChannel('cyberscan/native');
  static bool get _android => !kIsWeb && defaultTargetPlatform == TargetPlatform.android;
  static bool get supported => _android;

  static Future<T?> _call<T>(String method, [Object? args]) async {
    if (!_android) return null;
    try {
      return await _ch.invokeMethod<T>(method, args);
    } on MissingPluginException {
      return null;
    } on PlatformException {
      return null;
    }
  }

  /// Starts listening; returns whatever arrived before the app was ready (the share that opened it).
  static Future<Incoming?> listen(void Function(Incoming) onIncoming) async {
    // Android (MainActivity.kt) and iOS (AppDelegate.swift + ios/ShareExtension) both answer this.
    final ios = !kIsWeb && defaultTargetPlatform == TargetPlatform.iOS;
    if (!_android && !ios) return null;
    _ch.setMethodCallHandler((call) async {
      if (call.method == 'incoming') {
        final i = Incoming.fromMap(call.arguments);
        if (i != null) onIncoming(i);
      }
      return null;
    });
    try {
      return Incoming.fromMap(await _ch.invokeMethod<Object>('ready'));
    } on MissingPluginException {
      return null;
    } on PlatformException {
      return null;
    }
  }

  static Future<void> updateWidget({required String verdict, required String label, required String target, required int score,
          required String when, required String button, required String empty}) =>
      _call('updateWidget', {'verdict': verdict, 'label': label, 'target': target, 'score': score, 'when': when, 'button': button, 'empty': empty});

  static Future<void> clearShared() => _call('clearShared');

  /// The folder the user granted (name, still granted?), or null.
  static Future<Map<String, dynamic>?> folder() async {
    final m = await _call<Map>('folder');
    return m == null ? null : Map<String, dynamic>.from(m);
  }

  static Future<Map<String, dynamic>?> pickFolder() async {
    final m = await _call<Map>('pickFolder');
    return m == null ? null : Map<String, dynamic>.from(m);
  }

  static Future<void> forgetFolder() => _call('forgetFolder');

  static Future<List<FolderFile>?> listFolder() async {
    final l = await _call<List>('listFolder');
    return l
        ?.whereType<Map>()
        .map((m) => FolderFile(m['uri'].toString(), m['name'].toString(), (m['size'] as num?)?.toInt() ?? -1, (m['modified'] as num?)?.toInt() ?? 0))
        .toList();
  }

  static Future<SharedFile?> copyDocument(String uri) async {
    final m = await _call<Map>('copyDocument', {'uri': uri});
    if (m == null) return null;
    return SharedFile(m['name']?.toString() ?? 'file', m['path'] as String?, (m['size'] as num?)?.toInt() ?? -1, m['tooBig'] == true);
  }
}
