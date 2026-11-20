// Command and script tradecraft: patterns that show up in malware droppers and loaders.
// Each one is explained; none of them is proof on its own, so the weights stay honest.
import 'model.dart';

class Pattern {
  final String id;
  final RegExp re;
  final Severity severity;
  final int weight;
  final String titleEn, titleAr, detailEn, detailAr;
  const Pattern(this.id, this.re, this.severity, this.weight, this.titleEn, this.titleAr, this.detailEn, this.detailAr);
}

final List<Pattern> tradecraft = [
  Pattern('ps_encoded', RegExp(r'powershell(\.exe)?[^\n]{0,80}\s-(e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{16,}', caseSensitive: false),
      Severity.high, 55, 'Hidden PowerShell command', 'أمر PowerShell مخفي',
      'An encoded PowerShell command hides what it really does. Droppers use this to download and run malware.',
      'أمر PowerShell مُرمَّز يخفي ما يفعله فعلًا. تستخدمه البرامج الضارة لتنزيل برامج أخرى وتشغيلها.'),
  Pattern('ps_hidden', RegExp(r'powershell(\.exe)?[^\n]{0,60}(-w(indowstyle)?\s+hidden|-nop\b|-noprofile)', caseSensitive: false),
      Severity.medium, 30, 'PowerShell set to run hidden', 'PowerShell يعمل بشكل مخفي',
      'PowerShell is told to run without a window or profile, a common way to stay unnoticed.',
      'يُطلب من PowerShell العمل دون نافذة أو ملف تعريف، وهي طريقة شائعة للتخفي.'),
  Pattern('download_exec', RegExp(r'(downloadstring|downloadfile|invoke-webrequest|iwr\s|start-bitstransfer|net\.webclient)[\s\S]{0,120}(iex|invoke-expression|start-process|\.exe)', caseSensitive: false),
      Severity.high, 60, 'Downloads and runs code', 'ينزّل كودًا ويشغّله',
      'It fetches something from the internet and runs it straight away.',
      'يجلب شيئًا من الإنترنت ويشغّله مباشرة.'),
  Pattern('iex', RegExp(r'\b(iex|invoke-expression)\s*\(', caseSensitive: false),
      Severity.medium, 30, 'Runs code built at run time', 'يشغّل كودًا يُبنى أثناء التشغيل',
      'Invoke-Expression runs text as code, often after decoding it, so the real behaviour is hidden.',
      'ينفّذ النص ككود، غالبًا بعد فك ترميزه، فيبقى السلوك الحقيقي مخفيًا.'),
  Pattern('shadow_delete', RegExp(r'(vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete\s+catalog)', caseSensitive: false),
      Severity.critical, 80, 'Deletes backup copies', 'يحذف النسخ الاحتياطية',
      'Deleting Windows shadow copies prevents recovery. Ransomware does this right before encrypting files.',
      'حذف النسخ الاحتياطية في ويندوز يمنع الاسترجاع، وتفعل ذلك برامج الفدية قبل تشفير الملفات.'),
  Pattern('certutil', RegExp(r'certutil(\.exe)?\s+[^\n]{0,40}-(urlcache|decode)', caseSensitive: false),
      Severity.high, 50, 'Abuses a Windows tool to download or decode', 'يستغل أداة ويندوز للتنزيل أو فك الترميز',
      'certutil is a legitimate tool often misused to fetch or unpack malware.',
      'أداة certutil شرعية لكنها تُستغل كثيرًا لجلب البرامج الضارة أو فكّها.'),
  Pattern('lolbin', RegExp(r'(mshta(\.exe)?\s+(https?|vbscript|javascript):|regsvr32(\.exe)?\s+[^\n]{0,30}/i:https?|rundll32(\.exe)?\s+javascript:|bitsadmin\s+/transfer)', caseSensitive: false),
      Severity.high, 55, 'Runs code through a built-in Windows program', 'يشغّل كودًا عبر برنامج ويندوز مدمج',
      'Built-in programs (mshta, regsvr32, rundll32, bitsadmin) are being used to run remote code.',
      'تُستخدم برامج ويندوز المدمجة لتشغيل كود من الإنترنت.'),
  Pattern('injection_apis', RegExp(r'VirtualAlloc(Ex)?[\s\S]{0,400}WriteProcessMemory[\s\S]{0,400}CreateRemoteThread', caseSensitive: false),
      Severity.high, 50, 'Code-injection functions together', 'دوال حقن كود مجتمعة',
      'These three functions together are the classic way to inject code into another program.',
      'اجتماع هذه الدوال الثلاث هو الطريقة المعروفة لحقن كود داخل برنامج آخر.'),
  Pattern('autorun', RegExp(r'(\\currentversion\\run\b|schtasks(\.exe)?\s+/create|startup\\[^\n]{0,40}\.(lnk|exe|vbs|bat))', caseSensitive: false),
      Severity.medium, 30, 'Starts itself with Windows', 'يشغّل نفسه مع ويندوز',
      'It adds itself to startup or scheduled tasks so it runs again after a restart.',
      'يضيف نفسه إلى بدء التشغيل أو المهام المجدولة ليعمل مجددًا بعد إعادة التشغيل.'),
  Pattern('defender_off', RegExp(r'(set-mppreference[^\n]{0,60}-disable|add-mppreference[^\n]{0,40}-exclusion|disableantispyware)', caseSensitive: false),
      Severity.high, 60, 'Tries to switch off antivirus', 'يحاول إيقاف برنامج الحماية',
      'It changes Microsoft Defender settings to disable it or exclude itself.',
      'يغيّر إعدادات Microsoft Defender لتعطيله أو استثناء نفسه.'),
  Pattern('reverse_shell', RegExp(r'(/bin/(ba)?sh\s+-i\s*>&\s*/dev/tcp/|nc(at)?\s+-e\s+/bin/(ba)?sh|socket\.socket[\s\S]{0,200}subprocess[\s\S]{0,100}/bin/sh)', caseSensitive: false),
      Severity.critical, 75, 'Remote control shell', 'صدفة تحكم عن بُعد',
      'It connects back to another computer and hands it a command shell.',
      'يتصل بجهاز آخر ويمنحه صلاحية تنفيذ الأوامر.'),
  Pattern('curl_pipe', RegExp(r'(curl|wget)\s+[^\n|]{4,200}\|\s*(ba)?sh\b', caseSensitive: false),
      Severity.medium, 35, 'Downloads a script and runs it', 'ينزّل سكربتًا ويشغّله',
      'A script from the internet is piped straight into the shell without being checked.',
      'يُمرَّر سكربت من الإنترنت مباشرة إلى الصدفة دون فحص.'),
  Pattern('js_obfuscation', RegExp(r'(eval\s*\(\s*(unescape|atob|String\.fromCharCode)|ActiveXObject\s*\(\s*["\x27](wscript\.shell|scripting\.filesystemobject))', caseSensitive: false),
      Severity.high, 50, 'Obfuscated script', 'سكربت مموَّه',
      'Script code decodes itself at run time or creates Windows shell objects, typical of malicious attachments.',
      'كود يفك ترميز نفسه أثناء التشغيل أو ينشئ كائنات صدفة ويندوز، كما في المرفقات الضارة.'),
];

/// Runs every tradecraft pattern over [text] and returns the findings (each pattern once).
List<Finding> scanTradecraft(String text) {
  final out = <Finding>[];
  for (final p in tradecraft) {
    if (p.re.hasMatch(text)) {
      out.add(finding(p.id, p.severity, p.weight, 'content', p.titleEn, p.titleAr, p.detailEn, p.detailAr));
    }
  }
  return out;
}

/// Secrets accidentally left in files or messages (values are never shown in full).
final List<(String, RegExp, String, String)> secretPatterns = [
  ('private_key', RegExp(r'-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'), 'A private key', 'مفتاح خاص'),
  ('aws_key', RegExp(r'\bAKIA[0-9A-Z]{16}\b'), 'An AWS access key', 'مفتاح وصول AWS'),
  ('github_token', RegExp(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'), 'A GitHub token', 'رمز GitHub'),
  ('google_key', RegExp(r'\bAIza[0-9A-Za-z\-_]{35}\b'), 'A Google API key', 'مفتاح Google API'),
  ('slack_token', RegExp(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b'), 'A Slack token', 'رمز Slack'),
  ('jwt', RegExp(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'), 'A login token (JWT)', 'رمز دخول (JWT)'),
];

List<Finding> scanSecrets(String text) {
  final out = <Finding>[];
  for (final (id, re, en, ar) in secretPatterns) {
    if (re.hasMatch(text)) {
      out.add(finding('secret_$id', Severity.medium, 25, 'privacy', 'Contains a secret: $en', 'يحتوي على سر: $ar',
          '$en is written in plain text. Anyone who gets this file or message can use it. Change it and remove it.',
          '$ar مكتوب كنص واضح، ويستطيع أي شخص يحصل على هذا الملف أو الرسالة استخدامه. غيّره واحذفه.'));
    }
  }
  return out;
}
