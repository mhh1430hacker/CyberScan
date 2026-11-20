// Link checks: the signs phishing links share, read from the link itself (nothing is opened).
import 'model.dart';

/// Brands phishing pages imitate most, with the domains they really use.
const Map<String, List<String>> brands = {
  'paypal': ['paypal.com', 'paypal.me'], 'apple': ['apple.com', 'icloud.com'], 'icloud': ['icloud.com'],
  'microsoft': ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com'], 'outlook': ['outlook.com', 'live.com', 'office.com'],
  'office365': ['office.com', 'microsoft.com'], 'google': ['google.com', 'gmail.com', 'youtube.com'], 'gmail': ['gmail.com', 'google.com'],
  'facebook': ['facebook.com', 'fb.com', 'fb.me'], 'instagram': ['instagram.com'], 'whatsapp': ['whatsapp.com', 'wa.me'],
  'netflix': ['netflix.com'], 'amazon': ['amazon.com', 'amazon.sa', 'amazon.ae', 'amazon.co.uk', 'amazonaws.com'],
  'binance': ['binance.com'], 'coinbase': ['coinbase.com'], 'metamask': ['metamask.io'],
  'dhl': ['dhl.com', 'dhl.de'], 'fedex': ['fedex.com'], 'aramex': ['aramex.com'], 'smsa': ['smsaexpress.com'], 'spl': ['splonline.com.sa'],
  'usps': ['usps.com'], 'linkedin': ['linkedin.com'], 'dropbox': ['dropbox.com'], 'docusign': ['docusign.com', 'docusign.net'],
  'adobe': ['adobe.com'], 'steam': ['steampowered.com', 'steamcommunity.com'], 'telegram': ['telegram.org', 't.me'],
  'tiktok': ['tiktok.com'], 'snapchat': ['snapchat.com'], 'twitter': ['twitter.com', 'x.com', 't.co'],
  'alrajhi': ['alrajhibank.com.sa'], 'alrajhibank': ['alrajhibank.com.sa'], 'absher': ['absher.sa'], 'tawakkalna': ['tawakkalna.gov.sa'],
  'stcpay': ['stcpay.com.sa'], 'mada': ['mada.com.sa'], 'snb': ['alahli.com', 'snb.com'], 'alinma': ['alinma.com'],
  'riyadbank': ['riyadbank.com'], 'chase': ['chase.com'], 'visa': ['visa.com'], 'mastercard': ['mastercard.com'], 'ebay': ['ebay.com'],
};

const shorteners = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 's.id', 'v.gd'};
const riskyTlds = {'zip', 'mov', 'xyz', 'top', 'click', 'link', 'work', 'gq', 'tk', 'ml', 'cf', 'ga', 'cam', 'rest', 'country', 'kim', 'support', 'icu', 'buzz', 'cyou', 'sbs', 'monster'};
const bait = {'login', 'signin', 'sign-in', 'verify', 'verification', 'account', 'secure', 'update', 'wallet', 'billing', 'payment', 'confirm', 'unlock', 'recovery', 'suspended', 'reset', 'password', 'otp', 'refund', 'invoice'};
const runnable = {'exe', 'scr', 'msi', 'bat', 'cmd', 'js', 'vbs', 'hta', 'ps1', 'apk', 'jar', 'lnk', 'iso', 'dll', 'com'};
const secondLevel = {'co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'gob', 'nic', 'mil', 'sch', 'ltd', 'plc'};

// Letters from other alphabets that look like Latin ones (the most used confusables).
const confusables = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'ɡ': 'g',
  'ո': 'n', 'ս': 'u', 'ⅼ': 'l', 'ӏ': 'l', 'ı': 'i', 'ɑ': 'a', 'ο': 'o', 'ν': 'v', 'τ': 't', 'κ': 'k', 'α': 'a', 'ρ': 'p', 'ε': 'e',
  '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't', '@': 'a', r'$': 's',
};

String skeleton(String s) => s.toLowerCase().split('').map((c) => confusables[c] ?? c).join();

String registeredDomain(String host) {
  final parts = host.split('.');
  if (parts.length <= 2) return host;
  final secondToLast = parts[parts.length - 2];
  if (secondLevel.contains(secondToLast) && parts.length >= 3) return parts.sublist(parts.length - 3).join('.');
  return parts.sublist(parts.length - 2).join('.');
}

bool _official(String host, List<String> domains) => domains.any((d) => host == d || host.endsWith('.$d'));

/// One-letter-off comparison (pyapl / paypa1 against paypal).
bool _nearMiss(String a, String b) {
  if ((a.length - b.length).abs() > 1 || a == b) return false;
  var i = 0, j = 0, edits = 0;
  while (i < a.length && j < b.length) {
    if (a[i] == b[j]) { i++; j++; continue; }
    if (++edits > 1) return false;
    if (a.length > b.length) { i++; } else if (b.length > a.length) { j++; } else { i++; j++; }
  }
  return edits + (a.length - i) + (b.length - j) <= 1;
}

class LinkReport {
  final Uri? uri;
  final String host;
  final List<Finding> findings;
  LinkReport(this.uri, this.host, this.findings);
}

LinkReport analyzeLink(String raw) {
  final findings = <Finding>[];
  var text = raw.trim();
  if (!RegExp(r'^[a-z][a-z0-9+.-]*:', caseSensitive: false).hasMatch(text)) text = 'http://$text';
  final uri = Uri.tryParse(text);
  if (uri == null || uri.host.isEmpty) {
    if (RegExp(r'^(javascript|data|vbscript):', caseSensitive: false).hasMatch(raw.trim())) {
      findings.add(finding('script_scheme', Severity.high, 60, 'link', 'A link that runs code', 'رابط يشغّل كودًا',
          'It starts with javascript:, data: or vbscript:, so opening it runs code instead of visiting a site.',
          'يبدأ بـ javascript: أو data: أو vbscript:، ففتحه يشغّل كودًا بدل زيارة موقع.'));
    }
    return LinkReport(uri, '', findings);
  }
  final host = uri.host.toLowerCase().replaceAll(RegExp(r'\.$'), '');
  final reg = registeredDomain(host);
  final path = '${uri.path}${uri.hasQuery ? '?${uri.query}' : ''}'.toLowerCase();

  if (raw.contains('@') && RegExp(r'^[a-z]+://[^/]*@', caseSensitive: false).hasMatch(text)) {
    findings.add(finding('userinfo', Severity.high, 55, 'link', 'The real address is hidden after "@"', 'العنوان الحقيقي مخفي بعد "@"',
        'Everything before "@" is ignored by the browser; the link really goes to $host.',
        'المتصفح يتجاهل كل ما قبل "@"؛ الرابط يذهب فعلًا إلى $host.'));
  }
  if (RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(host) || host.contains(':')) {
    findings.add(finding('ip_host', Severity.medium, 35, 'link', 'A bare IP address instead of a name', 'عنوان IP مجرد بدل اسم',
        'Real companies use their domain names. Links to raw IP addresses are common in phishing and malware.',
        'الشركات الحقيقية تستخدم أسماء نطاقاتها، وروابط عناوين IP المجردة شائعة في التصيّد والبرامج الضارة.'));
  }
  if (host.split('.').any((label) => label.startsWith('xn--'))) {
    findings.add(finding('punycode', Severity.high, 50, 'link', 'Look-alike letters in the address', 'حروف مشابهة في العنوان',
        'The address uses letters from another alphabet that look like normal ones, a classic way to fake a known site.',
        'يستخدم العنوان حروفًا من أبجدية أخرى تشبه الحروف العادية، وهي حيلة معروفة لتقليد المواقع.'));
  }
  // brand impersonation: a brand name (or a near-miss of it) outside the brand's own domains
  final hostSkeleton = skeleton(host.replaceAll('-', '').replaceAll('.', ' '));
  for (final entry in brands.entries) {
    final brand = entry.key;
    if (_official(host, entry.value)) continue;
    final labels = skeleton(host).split(RegExp(r'[.\-]'));
    final named = hostSkeleton.contains(brand) || labels.any((l) => l.length >= 4 && _nearMiss(l, brand));
    final inPath = path.contains(brand) && bait.any(path.contains);
    if (named || inPath) {
      findings.add(finding('brand_$brand', Severity.high, named ? 65 : 45, 'link', 'Pretends to be ${_cap(brand)}', 'ينتحل صفة ${_cap(brand)}',
          '${named ? 'The address' : 'The page path'} uses the name ${_cap(brand)}, but the site is $reg, not ${entry.value.first}.',
          '${named ? 'العنوان' : 'مسار الصفحة'} يستخدم اسم ${_cap(brand)}، لكن الموقع هو $reg وليس ${entry.value.first}.'));
      break;
    }
  }
  final tld = host.split('.').last;
  if (riskyTlds.contains(tld)) {
    findings.add(finding('risky_tld', Severity.low, 15, 'link', 'An ending often used by scams (.$tld)', 'امتداد يكثر في الاحتيال (.$tld)',
        'Cheap or unusual domain endings are used often in throwaway scam sites. It is not proof on its own.',
        'امتدادات النطاقات الرخيصة أو غير المعتادة تُستخدم كثيرًا في مواقع الاحتيال المؤقتة، وهذا ليس دليلًا وحده.'));
  }
  if (shorteners.contains(host)) {
    findings.add(finding('shortener', Severity.low, 15, 'link', 'A shortened link', 'رابط مختصر',
        "A short link hides where it really goes. Expand it before opening, or ask the sender.",
        'الرابط المختصر يخفي وجهته الحقيقية. افتح نسخته الكاملة أولًا أو اسأل المرسل.'));
  }
  if (host.split('.').length >= 5) {
    findings.add(finding('deep_subdomains', Severity.low, 15, 'link', 'Very long chain of sub-names', 'سلسلة طويلة جدًا من الأسماء الفرعية',
        'Many dots before the real domain ($reg) are used to make the start of the address look trustworthy.',
        'كثرة النقاط قبل النطاق الحقيقي ($reg) تُستخدم لتبدو بداية العنوان موثوقة.'));
  }
  final baitHits = bait.where((w) => host.contains(w) || path.contains(w)).toList();
  if (baitHits.length >= 2 || (baitHits.isNotEmpty && findings.any((f) => f.weight >= 35))) {
    findings.add(finding('bait_words', Severity.medium, 25, 'link', 'Login or payment words in the address', 'كلمات دخول أو دفع في العنوان',
        'Words like "${baitHits.take(3).join('", "')}" are used to make a fake page feel urgent and official.',
        'كلمات مثل "${baitHits.take(3).join('"، "')}" تُستخدم لتبدو الصفحة المزيفة رسمية وعاجلة.'));
  }
  final ext = uri.pathSegments.isEmpty ? '' : (uri.pathSegments.last.split('.').length > 1 ? uri.pathSegments.last.split('.').last.toLowerCase() : '');
  if (runnable.contains(ext)) {
    findings.add(finding('download_program', Severity.high, 50, 'link', 'Downloads a program (.$ext)', 'ينزّل برنامجًا (.$ext)',
        'The link leads straight to a file that can run on your device. Only install apps from official stores or sites.',
        'يؤدي الرابط مباشرة إلى ملف يمكن تشغيله على جهازك. ثبّت التطبيقات من المتاجر أو المواقع الرسمية فقط.'));
  }
  if (uri.scheme == 'http' && baitHits.isNotEmpty) {
    findings.add(finding('no_https', Severity.low, 10, 'link', 'Not encrypted (http)', 'غير مشفّر (http)',
        'A page asking for logins or payments without https sends what you type in the clear.',
        'صفحة تطلب الدخول أو الدفع دون https ترسل ما تكتبه دون تشفير.'));
  }
  if (uri.hasPort && ![80, 443].contains(uri.port)) {
    findings.add(finding('odd_port', Severity.low, 12, 'link', 'An unusual port (:${uri.port})', 'منفذ غير معتاد (:${uri.port})',
        'Normal websites don\'t need a port number in the address.', 'المواقع العادية لا تحتاج رقم منفذ في العنوان.'));
  }
  return LinkReport(uri, host, findings);
}

const _display = {
  'paypal': 'PayPal', 'icloud': 'iCloud', 'office365': 'Office 365', 'whatsapp': 'WhatsApp', 'linkedin': 'LinkedIn', 'docusign': 'DocuSign',
  'tiktok': 'TikTok', 'metamask': 'MetaMask', 'dhl': 'DHL', 'usps': 'USPS', 'smsa': 'SMSA', 'spl': 'SPL', 'fedex': 'FedEx', 'alrajhi': 'Al Rajhi',
  'alrajhibank': 'Al Rajhi Bank', 'stcpay': 'STC Pay', 'snb': 'SNB', 'riyadbank': 'Riyad Bank', 'ebay': 'eBay', 'youtube': 'YouTube',
};
String _cap(String s) => _display[s] ?? (s.isEmpty ? s : s[0].toUpperCase() + s.substring(1));

ScanResult checkLink(String raw) {
  final t0 = DateTime.now();
  final report = analyzeLink(raw);
  final facts = <Fact>[
    Fact('Address', 'العنوان', raw.trim()),
    if (report.host.isNotEmpty) Fact('Real site', 'الموقع الفعلي', registeredDomain(report.host)),
    if (report.uri != null && report.uri!.scheme.isNotEmpty) Fact('Protocol', 'البروتوكول', report.uri!.scheme),
  ];
  return ScanResult(kind: CheckKind.link, target: raw.trim(), when: t0, findings: report.findings, facts: facts,
      elapsedMs: DateTime.now().difference(t0).inMilliseconds);
}
