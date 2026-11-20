// The on-phone engine against synthetic samples (no real malware is used anywhere).
import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:cyberscan/engine/file_scan.dart';
import 'package:cyberscan/engine/link_scan.dart';
import 'package:cyberscan/engine/model.dart';
import 'package:cyberscan/engine/text_scan.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List bytesOf(String s) => Uint8List.fromList(latin1.encode(s));

Uint8List fakePe({String extra = ''}) {
  // a minimal PE: MZ header pointing at a PE header with one section
  final b = BytesBuilder();
  final dos = Uint8List(0x80);
  dos[0] = 0x4D; dos[1] = 0x5A;
  dos[0x3C] = 0x80;
  b.add(dos);
  final pe = Uint8List(24 + 0xE0 + 40);
  pe.setAll(0, [0x50, 0x45, 0, 0]);
  pe[6] = 1; // one section
  pe[20] = 0xE0; // optional header size
  final sec = 24 + 0xE0;
  pe.setAll(sec, ascii.encode('.text'));
  final rawPtr = 0x80 + pe.length;
  pe.buffer.asByteData().setUint32(sec + 16, 512, Endian.little);
  pe.buffer.asByteData().setUint32(sec + 20, rawPtr, Endian.little);
  pe.buffer.asByteData().setUint32(sec + 36, 0x60000020, Endian.little);
  b.add(pe);
  b.add(Uint8List(512));
  b.add(ascii.encode(extra));
  return b.toBytes();
}

void main() {
  group('files', () {
    test('a clean text file has no warning signs', () {
      final r = checkFile('notes.txt', bytesOf('Meeting at 10, bring the slides.\n'));
      expect(r.verdict, Verdict.clear);
      expect(r.score, 0);
      expect(r.sha256, isNotNull);
    });

    test('a program named like a PDF is suspicious', () {
      final r = checkFile('invoice.pdf.exe', fakePe());
      expect(r.findings.map((f) => f.id), contains('double_extension'));
      expect(r.verdict, Verdict.suspicious);
    });

    test('hidden direction characters in a name are caught', () {
      final r = checkFile('photo${String.fromCharCode(0x202E)}gpj.exe', fakePe());
      expect(r.findings.map((f) => f.id), contains('hidden_name_chars'));
    });

    test('a program with an image extension is a type mismatch', () {
      final r = checkFile('holiday.jpg', fakePe());
      expect(r.findings.map((f) => f.id), contains('type_mismatch'));
      expect(r.verdict, Verdict.suspicious);
    });

    test('commands inside a program are read', () {
      final r = checkFile('tool.exe', fakePe(extra: 'vssadmin delete shadows /all /quiet powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi'));
      final ids = r.findings.map((f) => f.id).toSet();
      expect(ids, containsAll(['shadow_delete', 'ps_encoded']));
      expect(r.score, greaterThanOrEqualTo(80));
    });

    test('a PDF with JavaScript and data after its end', () {
      final pdf = '%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n'
          'MZ This program cannot be run in DOS mode ${'A' * 64}';
      final r = checkFile('statement.pdf', bytesOf(pdf));
      final ids = r.findings.map((f) => f.id).toSet();
      expect(ids, containsAll(['pdf_active', 'after_eof']));
      expect(r.verdict, Verdict.suspicious);
    });

    test('a ZIP hiding a disguised program', () {
      final a = Archive()
        ..addFile(ArchiveFile.bytes('readme.txt', utf8.encode('hello')))
        ..addFile(ArchiveFile.bytes('scan_2026.pdf.exe', fakePe()));
      final zip = Uint8List.fromList(ZipEncoder().encode(a));
      final r = checkFile('documents.zip', zip);
      final ids = r.findings.map((f) => f.id).toSet();
      expect(ids, containsAll(['archive_disguised', 'archive_programs']));
      expect(r.verdict, Verdict.suspicious);
    });

    test('a .docx with macros it should not have', () {
      final a = Archive()
        ..addFile(ArchiveFile.bytes('[Content_Types].xml', utf8.encode('<Types/>')))
        ..addFile(ArchiveFile.bytes('word/document.xml', utf8.encode('<w:document/>')))
        ..addFile(ArchiveFile.bytes('word/vbaProject.bin', Uint8List(64)));
      final r = checkFile('report.docx', Uint8List.fromList(ZipEncoder().encode(a)));
      expect(r.findings.map((f) => f.id), contains('ooxml_macros'));
      expect(r.verdict, Verdict.suspicious);
    });

    test('an empty file says so', () {
      final r = checkFile('empty.bin', Uint8List(0));
      expect(r.findings.map((f) => f.id), contains('empty'));
      expect(r.verdict, Verdict.clear);
    });
  });

  group('links', () {
    test('a well-known site is clean', () {
      expect(checkLink('https://www.google.com/search?q=weather').verdict, Verdict.clear);
      expect(checkLink('https://www.alrajhibank.com.sa/').verdict, Verdict.clear);
    });

    test('brand impersonation is suspicious', () {
      final r = checkLink('http://paypal-login.secure-verify.top/account/update');
      expect(r.findings.map((f) => f.id), contains('brand_paypal'));
      expect(r.verdict, Verdict.suspicious);
    });

    test('a one-letter look-alike is caught', () {
      expect(checkLink('https://paypa1.com/signin').findings.map((f) => f.id), contains('brand_paypal'));
    });

    test('the "@" trick and IP addresses', () {
      final ids = checkLink('http://www.apple.com@192.168.10.5/login').findings.map((f) => f.id).toSet();
      expect(ids, containsAll(['userinfo', 'ip_host']));
    });

    test('punycode look-alikes', () {
      expect(checkLink('https://xn--pypal-4ve.com/').findings.map((f) => f.id), contains('punycode'));
    });

    test('a direct program download', () {
      expect(checkLink('https://files.example.net/update/WhatsApp.apk').findings.map((f) => f.id), contains('download_program'));
    });
  });

  group('messages', () {
    test('an ordinary message is clean', () {
      expect(checkText('See you tomorrow at the office, bring the charger.').verdict, Verdict.clear);
    });

    test('Arabic bank phishing', () {
      final r = checkText('عاجل: تم إيقاف حسابك في مصرف الراجحي. حدّث بيانات البطاقة خلال 24 ساعة عبر الرابط http://alrajhi-update.xyz/login');
      final ids = r.findings.map((f) => f.id).toSet();
      expect(ids, containsAll(['urgency', 'credentials', 'phishing_combo']));
      expect(r.verdict, Verdict.suspicious);
    });

    test('English OTP request', () {
      final r = checkText('Hi, I sent you a code by mistake, please share the code with me.');
      expect(r.findings.map((f) => f.id), contains('credentials'));
    });

    test('a delivery scam', () {
      final r = checkText('Your parcel is on hold. Pay the customs fee now: https://dhl-redelivery.click/pay');
      expect(r.verdict, Verdict.suspicious);
    });

    test('secrets pasted in a message are noticed', () {
      expect(checkText('my key is AKIAABCDEFGHIJKLMNOP thanks').findings.map((f) => f.id), contains('secret_aws_key'));
    });
  });

  test('results survive a round trip through storage', () {
    final r = checkFile('invoice.pdf.exe', fakePe());
    final back = ScanResult.fromJson(jsonDecode(jsonEncode(r.toJson())) as Map<String, dynamic>);
    expect(back.score, r.score);
    expect(back.findings.length, r.findings.length);
    expect(back.verdict, r.verdict);
  });
}
