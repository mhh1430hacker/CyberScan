// QR codes: the camera reads the code on the phone; the text inside is then checked.
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../main.dart';
import '../theme.dart';
import 'home_screen.dart';

class QrScreen extends StatefulWidget {
  const QrScreen({super.key});
  @override
  State<QrScreen> createState() => _QrScreenState();
}

class _QrScreenState extends State<QrScreen> {
  final _controller = MobileScannerController(formats: const [BarcodeFormat.qrCode], detectionSpeed: DetectionSpeed.noDuplicates);
  bool _done = false;

  @override
  void dispose() { _controller.dispose(); super.dispose(); }

  void _found(BarcodeCapture capture) {
    if (_done) return;
    final value = capture.barcodes.map((b) => b.rawValue).whereType<String>().firstOrNull;
    if (value == null || value.trim().isEmpty) return;
    _done = true;
    final isLink = RegExp(r'^(https?://|www\.)\S+$', caseSensitive: false).hasMatch(value.trim());
    Navigator.of(context).pushReplacement(MaterialPageRoute(builder: (_) => InputScreen(link: isLink, initial: value.trim())));
  }

  @override
  Widget build(BuildContext context) {
    final s = AppScope.of(context).s;
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(title: Text(s.scanQr), foregroundColor: Colors.white),
      body: Stack(children: [
        MobileScanner(
          controller: _controller,
          onDetect: _found,
          errorBuilder: (context, error) => Center(
            child: Padding(padding: const EdgeInsets.all(32), child: Text(s.qrDenied, textAlign: TextAlign.center, style: const TextStyle(color: Colors.white))),
          ),
        ),
        // the aiming frame
        Center(
          child: Container(
            width: 250, height: 250,
            decoration: BoxDecoration(border: Border.all(color: C.cyan, width: 3), borderRadius: BorderRadius.circular(26),
                boxShadow: [BoxShadow(color: C.cyan.withValues(alpha: .4), blurRadius: 24)]),
          ),
        ),
        Positioned(
          left: 24, right: 24, bottom: 48,
          child: Text(s.qrAim, textAlign: TextAlign.center, style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w600)),
        ),
      ]),
    );
  }
}
