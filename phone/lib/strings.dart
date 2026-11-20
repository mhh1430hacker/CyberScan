// Every word the interface shows, in English and Arabic.
class S {
  final bool ar;
  const S(this.ar);
  String _(String en, String arText) => ar ? arText : en;

  String get appName => 'CyberScan';
  String get navHome => _('Home', 'الرئيسية');
  String get navHistory => _('History', 'السجل');
  String get navTools => _('Tools', 'الأدوات');
  String get navSettings => _('Settings', 'الإعدادات');

  String get greeting => _('Check before you open', 'افحص قبل أن تفتح');
  String get onDevice => _('Everything is checked on this phone. Nothing is uploaded.', 'كل الفحص يتم على هذا الهاتف، ولا يُرفع أي شيء.');
  String get checkFile => _('Check a file', 'افحص ملفًا');
  String get checkFileSub => _('Documents, apps, archives, pictures', 'مستندات، تطبيقات، أرشيفات، صور');
  String get checkLink => _('Check a link', 'افحص رابطًا');
  String get checkLinkSub => _('Before you tap it', 'قبل أن تضغط عليه');
  String get checkText => _('Check a message', 'افحص رسالة');
  String get checkTextSub => _('SMS, email or chat', 'رسالة نصية أو بريد أو محادثة');
  String get scanQr => _('Scan a QR code', 'اقرأ رمز QR');
  String get scanQrSub => _('Then check the link inside', 'ثم افحص الرابط بداخله');
  String get checks => _('checks', 'فحص');
  String get warnings => _('warnings', 'تحذير');
  String get lastCheck => _('last check', 'آخر فحص');
  String get recent => _('Recent checks', 'آخر الفحوصات');
  String get seeAll => _('See all', 'عرض الكل');
  String get never => _('—', '—');

  String get linkHint => _('Paste or type a link', 'الصق أو اكتب رابطًا');
  String get textHint => _('Paste the message you received', 'الصق الرسالة التي وصلتك');
  String get paste => _('Paste', 'لصق');
  String get check => _('Check', 'افحص');
  String get checking => _('Checking…', 'جارٍ الفحص…');
  String get tooBig => _('This file is larger than 100 MB.', 'هذا الملف أكبر من 100 ميغابايت.');
  String get readFailed => _("The file couldn't be read.", 'تعذّرت قراءة الملف.');

  String verdict(String v) => switch (v) {
        'clear' => _('No warning signs', 'لا علامات تحذير'),
        'review' => _('Needs a closer look', 'يحتاج نظرة أدق'),
        _ => _('Suspicious', 'مشبوه'),
      };
  String advice(String v, String kind) => switch (v) {
        'clear' => _('None of the checks found a warning sign. That is not a guarantee: only open things you expected.',
            'لم تجد الفحوصات أي علامة تحذير. هذا ليس ضمانًا: افتح فقط ما كنت تتوقعه.'),
        'review' => _('Something here is worth a closer look. Read the findings before you trust it.',
            'هناك ما يستحق نظرة أدق. اقرأ النتائج قبل أن تثق به.'),
        _ => kind == 'link'
            ? _("Don't open this link. If it came in a message, delete the message.", 'لا تفتح هذا الرابط. وإن وصلك في رسالة فاحذفها.')
            : kind == 'text'
                ? _("Don't reply, don't tap its links and never share a code. Delete it.", 'لا ترد، ولا تضغط روابطها، ولا تشارك أي رمز أبدًا. احذفها.')
                : _("Don't open or run this file. Delete it unless you are sure where it came from.", 'لا تفتح هذا الملف ولا تشغّله. احذفه ما لم تكن متأكدًا من مصدره.'),
      };
  String get score => _('Score', 'الدرجة');
  String get scoreNote => _('An explainable indicator from 0 to 100, not a probability.', 'مؤشر قابل للشرح من 0 إلى 100، وليس احتمالًا.');
  String get findings => _('What we found', 'ما وجدناه');
  String get noFindings => _('Nothing stood out in any check.', 'لم يبرز أي شيء في أي فحص.');
  String get details => _('Details', 'التفاصيل');
  String get insideFile => _('Inside the file', 'داخل الملف');
  String get insideNote => _('Randomness of each part. Bright parts look packed or encrypted.', 'عشوائية كل جزء. الأجزاء الساطعة تبدو مضغوطة أو مشفّرة.');
  String get share => _('Share report', 'مشاركة التقرير');
  String get copy => _('Copy', 'نسخ');
  String get copied => _('Copied', 'نُسخ');
  String get checkAnother => _('Check something else', 'افحص شيئًا آخر');
  String took(int ms) => ms < 1000 ? _('Checked in $ms ms', 'فُحص في $ms ملّي ثانية') : _('Checked in ${(ms / 1000).toStringAsFixed(1)} s', 'فُحص في ${(ms / 1000).toStringAsFixed(1)} ث');
  String get limits => _('CyberScan reads without running anything. A program can do things that only show when it runs, so no check can prove a file is safe.',
      'يقرأ CyberScan دون تشغيل أي شيء. قد يفعل البرنامج أشياء لا تظهر إلا عند تشغيله، لذلك لا يستطيع أي فحص إثبات أن الملف آمن.');
  String sev(String s) => switch (s) {
        'critical' => _('Critical', 'حرج'), 'high' => _('High', 'مرتفع'), 'medium' => _('Medium', 'متوسط'), 'low' => _('Low', 'منخفض'), _ => _('Info', 'معلومة'),
      };

  String get historyEmpty => _('Your checks will appear here. They are kept only on this phone.', 'ستظهر فحوصاتك هنا، وتُحفظ على هذا الهاتف فقط.');
  String get search => _('Search', 'بحث');
  String get all => _('All', 'الكل');
  String get clearAll => _('Clear history', 'مسح السجل');
  String get clearConfirm => _('Remove every saved check from this phone?', 'حذف كل الفحوصات المحفوظة من هذا الهاتف؟');
  String get cancel => _('Cancel', 'إلغاء');
  String get remove => _('Remove', 'حذف');
  String get removed => _('Removed', 'حُذف');

  String get toolsLede => _('Quick checks that run on this phone.', 'فحوصات سريعة تعمل على هذا الهاتف.');
  String get verify => _('Verify a download', 'تحقّق من ملف منزَّل');
  String get verifySub => _('Compare its fingerprint with the publisher’s', 'قارن بصمته ببصمة الناشر');
  String get verifyHint => _('Fingerprint from the publisher (SHA-256, SHA-1 or MD5)', 'بصمة الناشر (SHA-256 أو SHA-1 أو MD5)');
  String get chooseFile => _('Choose the file', 'اختر الملف');
  String matchOk(String algo) => _('Matches ($algo): this is exactly the file that was published.', 'متطابقة ($algo): هذا هو الملف المنشور نفسه.');
  String get matchBad => _("Doesn't match: this file differs from the published one. Don't open it.", 'غير متطابقة: هذا الملف يختلف عن المنشور. لا تفتحه.');
  String get password => _('Password strength', 'قوة كلمة المرور');
  String get passwordSub => _('Checked here, never sent', 'تُفحص هنا ولا تُرسل');
  String get passwordHint => _('Type a password', 'اكتب كلمة مرور');
  List<String> get pwLevels => ar ? ['ضعيفة جدًا', 'ضعيفة', 'مقبولة', 'قوية', 'قوية جدًا'] : ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
  String get pwPrivacy => _('Not saved, not sent anywhere.', 'لا تُحفظ ولا تُرسل إلى أي مكان.');
  String pwCrack(String t) => _('A fast offline attack would need about $t to guess it.', 'هجوم سريع دون اتصال يحتاج نحو $t لتخمينها.');
  String get pwInstant => _('A fast offline attack could guess it in under a second.', 'هجوم سريع دون اتصال يخمّنها في أقل من ثانية.');
  String get pwForever => _('A fast offline attack would need more than a million years.', 'هجوم سريع دون اتصال يحتاج أكثر من مليون سنة.');
  String get pwCommon => _('It contains a very common password.', 'تحتوي على كلمة مرور شائعة جدًا.');
  String get pwRepeat => _('Avoid repeated characters (aaa, 111).', 'تجنّب تكرار الأحرف (aaa، 111).');
  String get pwSequence => _('Avoid sequences (1234, abcd, qwer).', 'تجنّب التسلسلات (1234، abcd، qwer).');
  String get pwYear => _('Years and dates are easy to guess.', 'السنوات والتواريخ سهلة التخمين.');
  String get pwLength => _('Use at least 12 characters; a few random words work well.', 'استخدم 12 حرفًا على الأقل؛ بضع كلمات عشوائية خيار جيد.');
  String get pwMix => _('Mix letters, numbers and symbols.', 'امزج الحروف والأرقام والرموز.');
  String get qrAim => _('Point the camera at a QR code', 'وجّه الكاميرا نحو رمز QR');
  String get qrDenied => _('Camera permission is needed to read QR codes.', 'يلزم إذن الكاميرا لقراءة رموز QR.');

  String get language => _('Language', 'اللغة');
  String get general => _('General', 'عام');
  String get haptics => _('Vibration', 'الاهتزاز');
  String get hapticsSub => _('A short buzz on results', 'اهتزاز قصير عند النتائج');
  String get keepHistory => _('Keep a history', 'الاحتفاظ بالسجل');
  String get keepHistorySub => _('Saved only on this phone', 'يُحفظ على هذا الهاتف فقط');
  String get privacy => _('Privacy', 'الخصوصية');
  String get privacyText => _(
      'CyberScan checks files, links and messages on this phone. It has no account, no ads and no analytics, and it never uploads what you check. '
          'The camera is used only to read QR codes, and nothing it sees is saved. Your history stays on this phone until you clear it.',
      'يفحص CyberScan الملفات والروابط والرسائل على هذا الهاتف. لا حساب ولا إعلانات ولا تحليلات، ولا يرفع أبدًا ما تفحصه. '
          'تُستخدم الكاميرا فقط لقراءة رموز QR ولا يُحفظ شيء مما تراه. يبقى سجلك على هذا الهاتف حتى تمسحه.');
  String get about => _('About', 'حول التطبيق');
  String get aboutText => _('A defensive tool that helps you decide. It doesn’t replace antivirus software or your own judgement.',
      'أداة دفاعية تساعدك على القرار، ولا تغني عن برامج الحماية ولا عن تقديرك.');
  String get version => _('Version', 'الإصدار');
  String get engineLine => _('On-device engine: file structure, program anatomy, documents, archives, links and messages',
      'محرك على الجهاز: بنية الملفات، وتشريح البرامج، والمستندات، والأرشيفات، والروابط، والرسائل');

  List<(String, String)> get intro => ar
      ? [('افحص قبل أن تفتح', 'تُفكَّك الملفات والروابط والرسائل دون أن تُشغَّل، وتُشرح كل نتيجة بكلمات واضحة.'),
          ('يبقى على هاتفك', 'كل الفحص يتم على هذا الجهاز. لا حساب، ولا رفع، ولا تتبّع.'),
          ('أدوات في جيبك', 'اقرأ رموز QR، وتحقق من الملفات المنزّلة، واختبر قوة كلمات المرور.')]
      : [('Check before you open', 'Files, links and messages are taken apart without being run, and every finding is explained in plain words.'),
          ('It stays on your phone', 'Every check runs on this device. No account, no uploads, no tracking.'),
          ('Tools in your pocket', 'Read QR codes, verify downloads and test password strength.')];
  String get next => _('Next', 'التالي');
  String get start => _('Start', 'ابدأ');
  String get skip => _('Skip', 'تخطَّ');
}
