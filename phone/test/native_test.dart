// Share to CyberScan: what MainActivity hands over is parsed safely.
import 'package:cyberscan/native.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('files share', () {
    final i = Incoming.fromMap({
      'type': 'files',
      'files': [
        {'name': 'invoice.pdf', 'path': '/cache/shared/1-invoice.pdf', 'size': 1200, 'tooBig': false},
        {'name': 'big.iso', 'path': null, 'size': 300 << 20, 'tooBig': true},
      ],
      'skipped': 1,
    })!;
    expect(i.type, 'files');
    expect(i.files.length, 2);
    expect(i.files.first.path, '/cache/shared/1-invoice.pdf');
    expect(i.files.last.tooBig, isTrue);
    expect(i.skipped, 1);
  });
  test('text share and junk', () {
    expect(Incoming.fromMap({'type': 'text', 'text': 'https://example.com'})!.text, 'https://example.com');
    expect(Incoming.fromMap(null), isNull);
    expect(Incoming.fromMap('nope'), isNull);
    expect(Incoming.fromMap({'type': 'files', 'files': ['bad', 3]})!.files, isEmpty);
  });
  test('native calls fail soft when the platform side is missing', () async {
    expect(await Native.folder(), isNull);
    expect(await Native.listFolder(), isNull);
  });
}
