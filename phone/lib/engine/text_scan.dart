// Message checks: SMS, email or chat text. Scams share the same moves in every language:
// urgency, a request for codes or passwords, money, and a link that isn't what it says.
import 'link_scan.dart';
import 'model.dart';
import 'patterns.dart';

final _urgency = RegExp(
    r'(urgent|immediately|within 24 hours|act now|final notice|last warning|account (will be )?(suspended|blocked|closed|locked)|'
    r'عاجل|فورًا|فورا|خلال 24 ساعة|إنذار نهائي|آخر تنبيه|سيتم (إيقاف|تعليق|إغلاق|حظر) (حسابك|بطاقتك)|تم (إيقاف|تعليق) حسابك)',
    caseSensitive: false);
final _credentials = RegExp(
    r'(verify your (account|identity|card)|confirm your (password|details|card)|update your (payment|billing|card)|enter your (password|pin|card)|'
    r'(send|share|give)( me| us)? (the |your )?(code|otp|pin|password)|'
    r'رمز التحقق|الرمز السري|كلمة المرور|أرسل (لي |لنا )?الرمز|شارك الرمز|حدّث بيانات|حدث بيانات|تحديث بيانات|أدخل بيانات البطاقة|تأكيد هويتك)',
    caseSensitive: false);
final _money = RegExp(
    r'(gift ?card|itunes card|bitcoin|crypto wallet|wire transfer|western union|you (have )?won|claim your (prize|reward|refund)|lottery|'
    r'بطاقة (هدايا|شحن)|ربحت|فزت|جائزة|استرداد مبلغ|حوالة|محفظة|عملات رقمية|سحب على)',
    caseSensitive: false);
final _delivery = RegExp(r'(your (parcel|package|shipment) (is|was) (on hold|held|delayed)|customs fee|redelivery|شحنتك|الطرد|رسوم (جمركية|التوصيل)|إعادة التوصيل)', caseSensitive: false);
final _link = RegExp(r'((https?://|www\.)[^\s<>"]+|\b[a-z0-9-]+(\.[a-z0-9-]+)+/[^\s<>"]*)', caseSensitive: false);

ScanResult checkText(String raw) {
  final t0 = DateTime.now();
  final text = raw.trim();
  final findings = <Finding>[];
  final urgency = _urgency.hasMatch(text), creds = _credentials.hasMatch(text), money = _money.hasMatch(text), parcel = _delivery.hasMatch(text);
  if (urgency) {
    findings.add(finding('urgency', Severity.medium, 25, 'message', 'Pressure to act fast', 'ضغط للتصرف بسرعة',
        'It threatens a deadline or a blocked account. Scammers rush people so they don\'t stop to check.',
        'يهدد بمهلة أو بإيقاف الحساب. المحتالون يستعجلون الناس حتى لا يتوقفوا للتحقق.'));
  }
  if (creds) {
    findings.add(finding('credentials', Severity.high, 50, 'message', 'Asks for a code, password or card details', 'يطلب رمزًا أو كلمة مرور أو بيانات بطاقة',
        'Banks and real services never ask you to send a verification code, password or full card number by message.',
        'البنوك والخدمات الحقيقية لا تطلب منك أبدًا إرسال رمز التحقق أو كلمة المرور أو رقم البطاقة كاملًا في رسالة.'));
  }
  if (money) {
    findings.add(finding('money', Severity.medium, 30, 'message', 'Prizes, refunds or unusual payments', 'جوائز أو استرداد أو مدفوعات غير معتادة',
        'Gift cards, crypto, wire transfers or a surprise prize are typical of scams.',
        'بطاقات الهدايا والعملات الرقمية والحوالات والجوائز المفاجئة من علامات الاحتيال المعتادة.'));
  }
  if (parcel) {
    findings.add(finding('parcel', Severity.medium, 25, 'message', 'A delivery problem that needs payment', 'مشكلة توصيل تتطلب دفعًا',
        'Fake delivery messages ask for a small fee to steal card details.',
        'رسائل التوصيل المزيفة تطلب مبلغًا صغيرًا لسرقة بيانات البطاقة.'));
  }
  // every link in the text is checked like a link
  final links = _link.allMatches(text).map((m) => m.group(0)!).toSet().take(5).toList();
  var worstLink = 0;
  for (final l in links) {
    final r = analyzeLink(l);
    for (final f in r.findings) {
      if (findings.any((x) => x.id == f.id)) continue;
      findings.add(Finding(id: f.id, severity: f.severity, weight: f.weight, category: 'link', titleEn: f.titleEn, titleAr: f.titleAr,
          detailEn: '${f.detailEn} (link: $l)', detailAr: '${f.detailAr} (الرابط: $l)'));
      if (f.weight > worstLink) worstLink = f.weight;
    }
  }
  // a link plus pressure or a credential request is the phishing pattern itself
  final signs = [urgency, creds, money, parcel].where((x) => x).length;
  if (links.isNotEmpty && signs >= 1 && (creds || worstLink >= 35 || signs >= 2)) {
    findings.add(finding('phishing_combo', Severity.high, 60, 'message', 'Looks like phishing', 'يبدو تصيّدًا',
        'A link together with ${creds ? 'a request for codes or passwords' : 'pressure or a money hook'}: the usual shape of a phishing message. Don\'t tap the link.',
        'رابط مع ${creds ? 'طلب رموز أو كلمات مرور' : 'ضغط أو إغراء مالي'}: هذا هو شكل رسائل التصيّد المعتاد. لا تضغط على الرابط.'));
  }
  findings.addAll(scanTradecraft(text));
  findings.addAll(scanSecrets(text));
  final words = text.split(RegExp(r'\s+'));
  return ScanResult(kind: CheckKind.text, target: words.take(8).join(' ') + (words.length > 8 ? '…' : ''), when: t0, findings: findings,
      facts: [Fact('Characters', 'الأحرف', '${text.length}'), Fact('Links found', 'الروابط', '${links.length}')],
      elapsedMs: DateTime.now().difference(t0).inMilliseconds);
}
