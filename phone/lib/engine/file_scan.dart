// File checks: the file is read as bytes and taken apart; it is never opened or run.
import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart';

import 'model.dart';
import 'patterns.dart';

const _runs = {'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'ps1', 'msi', 'cpl', 'lnk', 'jar', 'dll', 'apk', 'iso', 'img', 'reg'};
const _looksHarmless = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'csv', 'jpg', 'jpeg', 'png', 'gif', 'mp3', 'mp4', 'zip', 'heic', 'webp'};
final _hiddenChars = [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C, 0x200B, 0xFEFF].map(String.fromCharCode).toList();
const _eicar = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

/// What the content really is, from its first bytes (never from the name).
String sniff(Uint8List b) {
  bool starts(List<int> sig, [int at = 0]) => b.length >= at + sig.length && List.generate(sig.length, (i) => b[at + i] == sig[i]).every((x) => x);
  if (starts([0x4D, 0x5A])) return 'pe';
  if (starts([0x7F, 0x45, 0x4C, 0x46])) return 'elf';
  if (starts([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])) return 'ole';
  if (starts([0x50, 0x4B, 0x03, 0x04]) || starts([0x50, 0x4B, 0x05, 0x06])) return 'zip';
  if (latin1.decode(b.sublist(0, math.min(1024, b.length))).contains('%PDF-')) return 'pdf';
  if (starts([0x7B, 0x5C, 0x72, 0x74])) return 'rtf';
  if (starts([0x89, 0x50, 0x4E, 0x47])) return 'png';
  if (starts([0xFF, 0xD8, 0xFF])) return 'jpeg';
  if (starts([0x47, 0x49, 0x46, 0x38])) return 'gif';
  if (starts([0x52, 0x61, 0x72, 0x21])) return 'rar';
  if (starts([0x37, 0x7A, 0xBC, 0xAF])) return '7z';
  if (starts([0x43, 0x44, 0x30, 0x30, 0x31], 0x8001)) return 'iso';
  if (b.isEmpty) return 'empty';
  final sample = b.sublist(0, math.min(8192, b.length));
  final printable = sample.where((c) => c >= 0x20 || c == 9 || c == 10 || c == 13).length;
  return printable / sample.length > 0.92 && !sample.contains(0) ? 'text' : 'binary';
}

const _typeNames = {
  'pe': ('Windows program', 'برنامج ويندوز'), 'elf': ('Linux program', 'برنامج لينكس'), 'ole': ('Old Office document', 'مستند أوفيس قديم'),
  'zip': ('ZIP archive', 'أرشيف ZIP'), 'ooxml': ('Office document', 'مستند أوفيس'), 'apk': ('Android app', 'تطبيق أندرويد'), 'jar': ('Java program', 'برنامج جافا'),
  'pdf': ('PDF document', 'مستند PDF'), 'rtf': ('RTF document', 'مستند RTF'), 'png': ('PNG image', 'صورة PNG'), 'jpeg': ('JPEG image', 'صورة JPEG'),
  'gif': ('GIF image', 'صورة GIF'), 'rar': ('RAR archive', 'أرشيف RAR'), '7z': ('7-Zip archive', 'أرشيف 7-Zip'), 'iso': ('Disk image', 'صورة قرص'),
  'text': ('Text', 'نص'), 'binary': ('Binary data', 'بيانات ثنائية'), 'empty': ('Empty file', 'ملف فارغ'),
};
const _trueExt = {'pe': {'exe', 'dll', 'scr', 'sys', 'com', 'cpl', 'ocx', 'efi'}, 'pdf': {'pdf'}, 'png': {'png'}, 'jpeg': {'jpg', 'jpeg', 'jfif'}, 'gif': {'gif'},
  'zip': {'zip', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm', 'apk', 'jar', 'odt', 'ods', 'epub', 'xpi', 'crx', 'aab', 'ipa'}, 'ole': {'doc', 'xls', 'ppt', 'msi', 'msg', 'dot', 'xlt'},
  'rtf': {'rtf', 'doc'}, 'elf': {'so', 'elf', 'bin', 'run', ''}, 'rar': {'rar'}, '7z': {'7z'}, 'iso': {'iso', 'img'}};

double entropyOf(Uint8List b, [int start = 0, int? end]) {
  end ??= b.length;
  final n = end - start;
  if (n <= 0) return 0;
  final counts = List<int>.filled(256, 0);
  for (var i = start; i < end; i++) {
    counts[b[i]]++;
  }
  var h = 0.0;
  for (final c in counts) {
    if (c == 0) continue;
    final p = c / n;
    h -= p * math.log(p) / math.ln2;
  }
  return h;
}

/// Printable ASCII and UTF-16LE strings, so commands hidden inside binaries are read too.
String stringsOf(Uint8List b, {int limit = 8 << 20}) {
  final data = b.length > limit ? b.sublist(0, limit) : b;
  final out = StringBuffer();
  final run = StringBuffer();
  for (final c in data) {
    if ((c >= 0x20 && c < 0x7F) || c == 9) {
      run.writeCharCode(c);
    } else {
      if (run.length >= 6) out.writeln(run);
      run.clear();
    }
  }
  if (run.length >= 6) out.writeln(run);
  // UTF-16LE: letter, zero, letter, zero …
  final wide = StringBuffer();
  for (var i = 0; i + 1 < data.length; i += 2) {
    final c = data[i];
    if (data[i + 1] == 0 && c >= 0x20 && c < 0x7F) {
      wide.writeCharCode(c);
    } else {
      if (wide.length >= 6) out.writeln(wide);
      wide.clear();
    }
  }
  return out.toString();
}

int _u16(Uint8List b, int o) => o + 2 <= b.length ? b[o] | (b[o + 1] << 8) : 0;
int _u32(Uint8List b, int o) => o + 4 <= b.length ? b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24) : 0;

class _Pe {
  final List<(String, double, int, int, int)> sections; // name, entropy, raw offset, raw size, characteristics
  final int overlay;
  final bool ok;
  _Pe(this.sections, this.overlay, this.ok);
}

_Pe _parsePe(Uint8List b) {
  final lfanew = _u32(b, 0x3C);
  if (lfanew <= 0 || lfanew + 24 > b.length || _u32(b, lfanew) != 0x00004550) return _Pe([], 0, false);
  final count = _u16(b, lfanew + 6), optSize = _u16(b, lfanew + 20);
  var o = lfanew + 24 + optSize;
  final sections = <(String, double, int, int, int)>[];
  var end = 0;
  for (var i = 0; i < count && i < 96 && o + 40 <= b.length; i++, o += 40) {
    final name = latin1.decode(b.sublist(o, o + 8)).replaceAll('\x00', '');
    final rawSize = _u32(b, o + 16), rawPtr = _u32(b, o + 20), flags = _u32(b, o + 36);
    final s = math.min(rawPtr, b.length), e = math.min(rawPtr + rawSize, b.length);
    sections.add((name, e > s ? entropyOf(b, s, e) : 0, rawPtr, rawSize, flags));
    end = math.max(end, rawPtr + rawSize);
  }
  return _Pe(sections, end > 0 && end < b.length ? b.length - end : 0, sections.isNotEmpty);
}

/// The whole file check. [name] is the file name the person chose; [bytes] its content.
ScanResult checkFile(String name, Uint8List bytes) {
  final t0 = DateTime.now();
  final findings = <Finding>[];
  void add(Finding f) { if (!findings.any((x) => x.id == f.id)) findings.add(f); }
  var kind = sniff(bytes);
  final base = name.split(RegExp(r'[\\/]')).last;
  final clean = _hiddenChars.fold(base, (s, c) => s.replaceAll(c, ''));
  final parts = clean.toLowerCase().split('.');
  final ext = parts.length > 1 ? parts.last : '';
  final text = kind == 'text' ? utf8.decode(bytes.length > (4 << 20) ? bytes.sublist(0, 4 << 20) : bytes, allowMalformed: true) : stringsOf(bytes);

  // ---- the name
  if (clean != base) {
    add(finding('hidden_name_chars', Severity.high, 55, 'name', 'Hidden characters disguise the name', 'حروف مخفية تموّه الاسم',
        'The name contains invisible direction characters that make it read as something else. The real name is "$clean".',
        'يحتوي الاسم على حروف اتجاه غير مرئية تجعله يُقرأ كشيء آخر. الاسم الحقيقي هو "$clean".'));
  }
  if (parts.length > 2 && _runs.contains(ext) && _looksHarmless.contains(parts[parts.length - 2].trim())) {
    add(finding('double_extension', Severity.high, 60, 'name', 'Named like a document, really a program', 'اسمه كمستند وهو برنامج فعلًا',
        'It ends in .${parts[parts.length - 2]}.$ext: it looks like a .${parts[parts.length - 2]} but it is a .$ext that can run.',
        'ينتهي بـ .${parts[parts.length - 2]}.$ext: يبدو كملف .${parts[parts.length - 2]} لكنه .$ext يمكن تشغيله.'));
  }

  // ---- what it really is, against what it claims to be
  Archive? zip;
  if (kind == 'zip') {
    try {
      zip = ZipDecoder().decodeBytes(bytes, verify: false);
      final names = zip.files.map((f) => f.name.toLowerCase()).toSet();
      if (names.contains('[content_types].xml')) {
        kind = 'ooxml';
      } else if (names.contains('androidmanifest.xml') && names.any((n) => n.endsWith('.dex'))) {
        kind = 'apk';
      } else if (names.contains('meta-inf/manifest.mf') && names.any((n) => n.endsWith('.class'))) {
        kind = 'jar';
      }
    } catch (_) {
      add(finding('broken_zip', Severity.low, 12, 'structure', 'A damaged or deliberately broken archive', 'أرشيف تالف أو مكسور عمدًا',
          'The archive\'s directory can\'t be read. Damage happens, but malformed archives are also used to slip past scanners.',
          'لا يمكن قراءة فهرس الأرشيف. التلف يحدث، لكن الأرشيفات المشوهة تُستخدم أيضًا للتهرب من الفاحصات.'));
    }
  }
  final allowed = _trueExt[kind == 'ooxml' || kind == 'apk' || kind == 'jar' ? 'zip' : kind];
  if (ext.isNotEmpty && allowed != null && !allowed.contains(ext) && !(kind == 'text') && kind != 'binary') {
    final program = kind == 'pe' || kind == 'elf';
    add(finding('type_mismatch', program ? Severity.high : Severity.medium, program ? 60 : 30, 'name',
        'The name doesn\'t match the content', 'الاسم لا يطابق المحتوى',
        'It is named .$ext but the content is a ${_typeNames[kind]!.$1.toLowerCase()}.${program ? ' A program disguised as something else is a classic trick.' : ''}',
        'اسمه .$ext لكن محتواه ${_typeNames[kind]!.$2}.${program ? ' البرنامج المتنكر في هيئة شيء آخر حيلة معروفة.' : ''}'));
  }

  // ---- randomness across the file (packed or encrypted parts look random)
  final windows = <double>[];
  if (bytes.isNotEmpty) {
    final step = math.max(4096, (bytes.length / 160).ceil());
    for (var s = 0; s < bytes.length; s += step) {
      windows.add(double.parse(entropyOf(bytes, s, math.min(s + step, bytes.length)).toStringAsFixed(2)));
    }
  }
  final avg = bytes.isEmpty ? 0.0 : entropyOf(bytes);
  final compressedByDesign = {'png', 'jpeg', 'gif', 'zip', 'ooxml', 'apk', 'jar', 'pdf', 'rar', '7z'}.contains(kind);

  // ---- per format
  switch (kind) {
    case 'pe':
      add(finding('program', Severity.info, 0, 'program', 'A Windows program', 'برنامج ويندوز',
          'A fact, not a warning: it runs on Windows only and can\'t run on this phone.', 'معلومة وليست تحذيرًا: يعمل على ويندوز فقط ولا يمكن تشغيله على هذا الهاتف.'));
      final pe = _parsePe(bytes);
      if (!pe.ok) {
        add(finding('malformed_pe', Severity.medium, 30, 'program', 'A malformed program header', 'رأس برنامج مشوّه',
            'It starts like a Windows program but its headers are broken. Broken headers are used to confuse analysis tools.',
            'يبدأ كبرنامج ويندوز لكن رؤوسه مكسورة، وهذا يُستخدم لإرباك أدوات التحليل.'));
      } else {
        final packers = pe.sections.where((s) => RegExp(r'^(upx\d|\.aspack|\.adata|\.themida|\.vmp\d|\.mpress\d|\.petite|pec\d|\.nsp\d)', caseSensitive: false).hasMatch(s.$1)).map((s) => s.$1).toList();
        if (packers.isNotEmpty) {
          add(finding('packer', Severity.medium, 35, 'program', 'Packed program (${packers.first})', 'برنامج مضغوط (${packers.first})',
              'Packing squeezes and hides the real code. Some honest programs do it, but most malware does.',
              'الضغط يخفي الكود الحقيقي. بعض البرامج السليمة تفعل ذلك، لكن أغلب البرامج الضارة تفعله.'));
        }
        final hot = pe.sections.where((s) => s.$2 > 7.2 && s.$4 > 1024).map((s) => s.$1).toList();
        if (hot.isNotEmpty) {
          add(finding('high_entropy_section', Severity.medium, 25, 'program', 'Encrypted-looking program parts', 'أجزاء من البرنامج تبدو مشفّرة',
              'Section ${hot.take(2).join(', ')} looks random, typical of packed or encrypted code.',
              'القسم ${hot.take(2).join('، ')} يبدو عشوائيًا، وهذا معتاد في الكود المضغوط أو المشفّر.'));
        }
        final wx = pe.sections.where((s) => (s.$5 & 0x20000000) != 0 && (s.$5 & 0x80000000) != 0).map((s) => s.$1).toList();
        if (wx.isNotEmpty) {
          add(finding('writable_code', Severity.medium, 25, 'program', 'Code that can rewrite itself', 'كود يستطيع تعديل نفسه',
              'Section ${wx.first} is both writable and executable, which self-unpacking malware needs.',
              'القسم ${wx.first} قابل للكتابة والتنفيذ معًا، وهذا ما تحتاجه البرامج الضارة التي تفك نفسها.'));
        }
        if (pe.overlay > 0) {
          final tail = bytes.sublist(bytes.length - pe.overlay);
          final hidden = sniff(tail);
          final serious = hidden == 'pe' || hidden == 'zip';
          add(finding('pe_overlay', serious ? Severity.medium : Severity.low, serious ? 30 : 8, 'program', 'Extra data after the end of the program', 'بيانات إضافية بعد نهاية البرنامج',
              '${_size(pe.overlay)} sit after the program\'s last part.${serious ? ' It starts like another ${_typeNames[hidden]!.$1.toLowerCase()}.' : ' Installers often keep their payload there.'}',
              '${_size(pe.overlay)} بعد آخر جزء من البرنامج.${serious ? ' وتبدأ كـ${_typeNames[hidden]!.$2}.' : ' برامج التثبيت تحفظ محتواها هناك عادةً.'}'));
        }
      }
    case 'elf':
      add(finding('program', Severity.info, 0, 'program', 'A Linux program', 'برنامج لينكس', 'A fact, not a warning.', 'معلومة وليست تحذيرًا.'));
    case 'pdf':
      final raw = latin1.decode(bytes);
      final active = <String>[
        if (RegExp(r'/(JavaScript|JS)\b').hasMatch(raw)) 'JavaScript',
        if (RegExp(r'/(OpenAction|AA)\b').hasMatch(raw)) 'automatic actions',
        if (RegExp(r'/Launch\b').hasMatch(raw)) 'Launch',
        if (RegExp(r'/EmbeddedFiles?\b').hasMatch(raw)) 'embedded files',
      ];
      if (active.isNotEmpty) {
        final strong = active.contains('JavaScript') || active.contains('Launch');
        add(finding('pdf_active', strong ? Severity.high : Severity.medium, strong ? 50 : 25, 'document', 'Active content in the PDF', 'محتوى نشط داخل ملف PDF',
            'It carries ${active.join(', ')}. A normal document doesn\'t need to run anything when you open it.',
            'يحمل ${active.join('، ')}. المستند العادي لا يحتاج تشغيل أي شيء عند فتحه.'));
      }
      final eof = raw.lastIndexOf('%%EOF');
      if (eof > 0) {
        final after = bytes.sublist(eof + 5);
        final trimmed = after.where((c) => c != 0x20 && c != 0x0A && c != 0x0D && c != 0x00).length;
        if (trimmed > 32) {
          final starts = sniff(Uint8List.fromList(after.skipWhile((c) => c == 0x0A || c == 0x0D || c == 0x20).toList()));
          final serious = starts == 'pe' || starts == 'zip' || starts == 'text';
          add(finding('after_eof', serious ? Severity.high : Severity.medium, serious ? 45 : 25, 'structure', 'Data hidden after the end of the file', 'بيانات مخفية بعد نهاية الملف',
              '${_size(trimmed)} are stored after the point where the PDF ends. Readers ignore it; other programs can use it.',
              '${_size(trimmed)} مخزنة بعد نهاية ملف PDF. القارئ يتجاهلها، لكن برامج أخرى تستطيع استخدامها.'));
        }
      }
    case 'ole':
      if (text.contains('_VBA_PROJECT') || text.contains('Attribute VB_')) {
        final auto = RegExp(r'(AutoOpen|Document_Open|Workbook_Open|Auto_Open)', caseSensitive: false).hasMatch(text);
        add(finding('macros', auto ? Severity.high : Severity.medium, auto ? 55 : 30, 'document', auto ? 'Macros that run when it opens' : 'Macros (VBA code)',
            auto ? 'ماكرو يعمل عند الفتح' : 'ماكرو (كود VBA)',
            auto ? 'The document carries code set to run automatically on opening. Keep macros disabled.' : 'The document carries code. Keep macros disabled unless you trust the sender.',
            auto ? 'يحمل المستند كودًا مضبوطًا ليعمل تلقائيًا عند الفتح. أبقِ الماكرو معطّلًا.' : 'يحمل المستند كودًا. أبقِ الماكرو معطّلًا ما لم تثق بالمرسل.'));
      }
    case 'rtf':
      final raw = latin1.decode(bytes);
      if (raw.contains(r'\objdata') || raw.contains(r'\objupdate')) {
        add(finding('rtf_object', Severity.high, 45, 'document', 'Embedded objects in the document', 'كائنات مضمّنة في المستند',
            'RTF files with embedded objects have been used to exploit Office (e.g. Equation Editor attacks).',
            'ملفات RTF التي تحمل كائنات مضمّنة استُخدمت لاستغلال أوفيس (مثل هجمات محرر المعادلات).'));
      }
    case 'png' || 'jpeg' || 'gif':
      final endAt = _imageEnd(bytes, kind);
      if (endAt > 0 && bytes.length - endAt > 32) {
        final tail = bytes.sublist(endAt);
        final hidden = sniff(tail);
        final serious = hidden == 'pe' || hidden == 'zip';
        add(finding('after_image', serious ? Severity.high : Severity.low, serious ? 50 : 10, 'structure', 'Data hidden after the picture', 'بيانات مخفية بعد الصورة',
            '${_size(tail.length)} follow the end of the image.${serious ? ' They start like a ${_typeNames[hidden]!.$1.toLowerCase()}.' : ' Some phones store motion-photo videos there.'}',
            '${_size(tail.length)} بعد نهاية الصورة.${serious ? ' وتبدأ كـ${_typeNames[hidden]!.$2}.' : ' بعض الهواتف تحفظ هناك فيديو الصورة المتحركة.'}'));
      }
  }

  // ---- archives and Office packages: what's inside
  if (zip != null) {
    final risky = <String>[], disguised = <String>[], traversal = <String>[];
    var total = 0;
    for (final f in zip.files) {
      if (!f.isFile) continue;
      total++;
      final n = f.name;
      final lower = n.toLowerCase();
      final p = lower.split('/').last.split('.');
      final e = p.length > 1 ? p.last : '';
      if (n.contains('..') || n.startsWith('/') || n.contains(':')) traversal.add(n);
      if (_runs.contains(e) && kind == 'zip') risky.add(n);
      if (p.length > 2 && _runs.contains(e) && _looksHarmless.contains(p[p.length - 2])) disguised.add(n);
      // a member that unpacks to far more than the whole archive weighs: a decompression bomb
      if (f.size > 100 * bytes.length && f.size > 200 << 20) {
        add(finding('zip_bomb', Severity.high, 50, 'archive', 'Built to overwhelm on extraction', 'مصمم لإغراق الجهاز عند الفك',
            '$n expands to ${_size(f.size)} from an archive of ${_size(bytes.length)}: a decompression bomb.',
            '$n يتمدد إلى ${_size(f.size)} من أرشيف حجمه ${_size(bytes.length)}: قنبلة ضغط.'));
      }
      if (kind == 'ooxml' && lower.endsWith('vbaproject.bin')) {
        final macroExt = {'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'ppsm', 'xlsb'}.contains(ext);
        add(finding('ooxml_macros', macroExt ? Severity.medium : Severity.high, macroExt ? 30 : 55, 'document', 'Macros (VBA code)', 'ماكرو (كود VBA)',
            macroExt ? 'The document carries code. Keep macros disabled unless you trust the sender.' : 'A .$ext file isn\'t supposed to contain macros at all, yet this one does.',
            macroExt ? 'يحمل المستند كودًا. أبقِ الماكرو معطّلًا ما لم تثق بالمرسل.' : 'ملف .$ext لا يُفترض أن يحتوي ماكرو أصلًا، لكن هذا الملف يحتوي.'));
      }
      if (kind == 'ooxml' && lower.endsWith('.rels') && f.size < 256 << 10) {
        final xml = utf8.decode(f.readBytes() ?? Uint8List(0), allowMalformed: true);
        if (RegExp(r'Type="[^"]*/(attachedTemplate|oleObject|frame|subDocument)"[^>]*TargetMode="External"|TargetMode="External"[^>]*Type="[^"]*/(attachedTemplate|oleObject|frame|subDocument)"').hasMatch(xml)) {
          add(finding('remote_template', Severity.high, 55, 'document', 'Loads something from the internet when opened', 'يحمّل شيئًا من الإنترنت عند الفتح',
              'The document points to a remote template or object. This "template injection" is used to deliver malware.',
              'يشير المستند إلى قالب أو كائن بعيد. هذا "حقن القالب" يُستخدم لإيصال البرامج الضارة.'));
        }
      }
      // small text-like members are read for commands too
      if (f.size < 2 << 20 && {'js', 'vbs', 'ps1', 'bat', 'cmd', 'hta', 'wsf', 'sh', 'py', 'txt', 'xml', 'html', 'htm', 'lnk'}.contains(e)) {
        for (final x in scanTradecraft(utf8.decode(f.readBytes() ?? Uint8List(0), allowMalformed: true))) {
          add(Finding(id: x.id, severity: x.severity, weight: x.weight, category: 'archive', titleEn: x.titleEn, titleAr: x.titleAr,
              detailEn: '${x.detailEn} (inside $n)', detailAr: '${x.detailAr} (داخل $n)'));
        }
      }
    }
    if (risky.isNotEmpty) {
      add(finding('archive_programs', Severity.medium, 30, 'archive', 'Programs or scripts inside the archive', 'برامج أو سكربتات داخل الأرشيف',
          '${risky.length} of $total files can run: ${risky.take(3).join(', ')}. Archives are a common way to deliver malware by email.',
          '${risky.length} من $total ملفات يمكن تشغيلها: ${risky.take(3).join('، ')}. الأرشيفات طريقة شائعة لإيصال البرامج الضارة بالبريد.'));
    }
    if (disguised.isNotEmpty) {
      add(finding('archive_disguised', Severity.high, 60, 'archive', 'A disguised program inside the archive', 'برنامج متنكر داخل الأرشيف',
          '${disguised.first} is named like a document but is a program.', '${disguised.first} اسمه كمستند لكنه برنامج.'));
    }
    if (traversal.isNotEmpty) {
      add(finding('zip_slip', Severity.high, 50, 'archive', 'Paths that escape the folder', 'مسارات تخرج من المجلد',
          '${traversal.first} would be written outside the extraction folder ("zip slip").', '${traversal.first} سيُكتب خارج مجلد الفك ("zip slip").'));
    }
    if (kind == 'apk') {
      add(finding('android_app', Severity.info, 0, 'program', 'An Android app', 'تطبيق أندرويد',
          'Install apps only from Google Play or a publisher you trust. Apps sent by message are a common way to steal banking details.',
          'ثبّت التطبيقات من Google Play أو من ناشر تثق به فقط. التطبيقات المرسلة في الرسائل طريقة شائعة لسرقة البيانات البنكية.'));
    }
  }

  // ---- commands, scripts and secrets, in every format
  for (final f in scanTradecraft(text)) {
    add(f);
  }
  if (kind == 'text') {
    for (final f in scanSecrets(text)) {
      add(f);
    }
  }
  if (text.contains(_eicar) || latin1.decode(bytes.length > 4096 ? bytes.sublist(0, 4096) : bytes).contains(_eicar)) {
    add(finding('eicar', Severity.high, 60, 'content', 'The EICAR anti-malware test file', 'ملف اختبار EICAR لبرامج الحماية',
        'A harmless file that exists so people can check their protection reacts. CyberScan reports it like antivirus products do.',
        'ملف غير ضار وُجد ليتحقق الناس أن برنامج الحماية يستجيب. يبلّغ عنه CyberScan كما تفعل برامج الحماية.'));
  }
  if (!compressedByDesign && kind != 'pe' && avg > 7.5 && bytes.length > 4096) {
    add(finding('high_entropy', Severity.low, 15, 'content', 'The content looks random', 'المحتوى يبدو عشوائيًا',
        'Almost every byte is unpredictable, typical of encrypted or compressed data. It is not proof on its own.',
        'كل بايت تقريبًا غير متوقع، وهذا معتاد في البيانات المشفّرة أو المضغوطة، وليس دليلًا وحده.'));
  }
  if (bytes.isEmpty) {
    add(finding('empty', Severity.info, 0, 'content', 'The file is empty', 'الملف فارغ', 'There is nothing to analyse.', 'لا يوجد ما يمكن تحليله.'));
  }

  final digest = sha256.convert(bytes).toString();
  final type = _typeNames[kind] ?? ('Unknown', 'غير معروف');
  return ScanResult(
    kind: CheckKind.file,
    target: clean,
    when: t0,
    findings: findings,
    sha256: digest,
    entropyMap: windows,
    elapsedMs: DateTime.now().difference(t0).inMilliseconds,
    facts: [
      Fact('Size', 'الحجم', _size(bytes.length)),
      Fact('Real type', 'النوع الفعلي', '${type.$1} · ${type.$2}'),
      Fact('Randomness', 'العشوائية', '${avg.toStringAsFixed(2)} / 8'),
      Fact('SHA-256', 'SHA-256', digest),
      Fact('MD5', 'MD5', md5.convert(bytes).toString()),
    ],
  );
}

int _imageEnd(Uint8List b, String kind) {
  if (kind == 'png') {
    for (var i = 8; i + 8 <= b.length; i++) {
      if (b[i] == 0x49 && b[i + 1] == 0x45 && b[i + 2] == 0x4E && b[i + 3] == 0x44) return math.min(i + 8, b.length);
    }
  } else if (kind == 'jpeg') {
    for (var i = b.length - 2; i > 2; i--) {
      if (b[i] == 0xFF && b[i + 1] == 0xD9) {
        // the last end marker followed by non-image data
        return i + 2;
      }
    }
  } else if (kind == 'gif') {
    for (var i = b.length - 1; i > 6; i--) {
      if (b[i] == 0x3B) return i + 1;
    }
  }
  return 0;
}

String _size(int n) => n < 1024 ? '$n B' : n < 1 << 20 ? '${(n / 1024).toStringAsFixed(1)} KB' : '${(n / (1 << 20)).toStringAsFixed(1)} MB';
