"""Search-result text for every page: the title and description people see on Google, Bing and in
shared links, in the page's language (web_v/site_extras.py decorate() applies it).

Titles stay under ~60 characters and descriptions under ~160, the lengths search engines show in
full; each says what the page does in the words people search with. The landing page is written
in all 30 site languages; the other pages in English and Arabic (other languages use English).
"""
from __future__ import annotations

import html
import json
import re

SITE = "https://ainex-ai.xyz"

# ---------------------------------------------------------------- the landing page, 30 languages
HOME = {
    "en": ("CyberScan: free file & link scanner, explained in plain words",
           "Check any file, link or message for malware and phishing before you open it. Free, private analysis with 5,000+ threat rules, clear verdicts and safe repair."),
    "ar": ("CyberScan | افحص الملفات والروابط قبل فتحها مجانًا",
           "افحص أي ملف أو رابط أو رسالة بحثًا عن البرمجيات الخبيثة والتصيّد قبل فتحها. فحص مجاني وخاص بأكثر من 5,000 قاعدة تهديد، ونتيجة واضحة بلغة بسيطة، وإصلاح آمن."),
    "fr": ("CyberScan : analyse gratuite de fichiers et de liens",
           "Vérifiez un fichier, un lien ou un message avant de l'ouvrir : logiciels malveillants, hameçonnage. Analyse gratuite et privée, verdict clair, réparation sûre."),
    "es": ("CyberScan: analiza archivos y enlaces gratis",
           "Comprueba cualquier archivo, enlace o mensaje antes de abrirlo: malware y phishing. Análisis gratuito y privado, veredicto claro y reparación segura."),
    "de": ("CyberScan: Dateien & Links kostenlos prüfen",
           "Prüfen Sie Dateien, Links und Nachrichten vor dem Öffnen auf Malware und Phishing. Kostenlose, private Analyse mit klarem Ergebnis und sicherer Reparatur."),
    "pt": ("CyberScan: analise arquivos e links grátis",
           "Verifique qualquer arquivo, link ou mensagem antes de abrir: malware e phishing. Análise gratuita e privada, resultado claro e reparo seguro."),
    "it": ("CyberScan: analisi gratuita di file e link",
           "Controlla file, link e messaggi prima di aprirli: malware e phishing. Analisi gratuita e privata, verdetto chiaro e riparazione sicura."),
    "nl": ("CyberScan: gratis bestanden en links scannen",
           "Controleer elk bestand, elke link of elk bericht op malware en phishing voordat je het opent. Gratis en privé, met een duidelijk oordeel en veilig herstel."),
    "tr": ("CyberScan: dosya ve bağlantıları ücretsiz tarayın",
           "Açmadan önce her dosyayı, bağlantıyı veya mesajı kötü amaçlı yazılım ve oltalamaya karşı kontrol edin. Ücretsiz, gizli, açık sonuç ve güvenli onarım."),
    "ru": ("CyberScan: бесплатная проверка файлов и ссылок",
           "Проверьте любой файл, ссылку или сообщение на вирусы и фишинг до открытия. Бесплатный и приватный анализ, понятный вердикт и безопасное восстановление."),
    "uk": ("CyberScan: безкоштовна перевірка файлів і посилань",
           "Перевірте будь-який файл, посилання чи повідомлення на шкідливе ПЗ і фішинг до відкриття. Безкоштовно й приватно, зрозумілий вердикт і безпечне відновлення."),
    "pl": ("CyberScan: darmowe skanowanie plików i linków",
           "Sprawdź plik, link lub wiadomość pod kątem złośliwego oprogramowania i phishingu przed otwarciem. Za darmo i prywatnie, z jasnym werdyktem i bezpieczną naprawą."),
    "fa": ("CyberScan | بررسی رایگان فایل‌ها و لینک‌ها",
           "هر فایل، لینک یا پیام را پیش از باز کردن برای بدافزار و فیشینگ بررسی کنید. تحلیل رایگان و خصوصی، نتیجهٔ روشن و ترمیم امن."),
    "ur": ("CyberScan | فائلیں اور لنکس مفت چیک کریں",
           "کسی بھی فائل، لنک یا پیغام کو کھولنے سے پہلے میلویئر اور فشنگ کے لیے چیک کریں۔ مفت اور نجی تجزیہ، واضح نتیجہ اور محفوظ مرمت۔"),
    "hi": ("CyberScan: फ़ाइलें और लिंक मुफ़्त में जाँचें",
           "किसी भी फ़ाइल, लिंक या संदेश को खोलने से पहले मैलवेयर और फ़िशिंग के लिए जाँचें। मुफ़्त और निजी विश्लेषण, साफ़ नतीजा और सुरक्षित मरम्मत।"),
    "bn": ("CyberScan: বিনামূল্যে ফাইল ও লিংক স্ক্যান",
           "খোলার আগে যেকোনো ফাইল, লিংক বা বার্তা ম্যালওয়্যার ও ফিশিংয়ের জন্য পরীক্ষা করুন। বিনামূল্যে ও ব্যক্তিগত বিশ্লেষণ, স্পষ্ট ফলাফল ও নিরাপদ মেরামত।"),
    "pa": ("CyberScan: ਫ਼ਾਈਲਾਂ ਅਤੇ ਲਿੰਕ ਮੁਫ਼ਤ ਜਾਂਚੋ",
           "ਖੋਲ੍ਹਣ ਤੋਂ ਪਹਿਲਾਂ ਕਿਸੇ ਵੀ ਫ਼ਾਈਲ, ਲਿੰਕ ਜਾਂ ਸੁਨੇਹੇ ਨੂੰ ਮਾਲਵੇਅਰ ਅਤੇ ਫ਼ਿਸ਼ਿੰਗ ਲਈ ਜਾਂਚੋ। ਮੁਫ਼ਤ ਤੇ ਨਿੱਜੀ ਵਿਸ਼ਲੇਸ਼ਣ, ਸਾਫ਼ ਨਤੀਜਾ।"),
    "gu": ("CyberScan: ફાઇલો અને લિંક મફતમાં તપાસો",
           "ખોલતાં પહેલાં કોઈપણ ફાઇલ, લિંક કે સંદેશને મૉલવેર અને ફિશિંગ માટે તપાસો. મફત અને ખાનગી વિશ્લેષણ, સ્પષ્ટ પરિણામ અને સુરક્ષિત સુધારો."),
    "mr": ("CyberScan: फाइल्स आणि लिंक मोफत तपासा",
           "उघडण्यापूर्वी कोणतीही फाइल, लिंक किंवा संदेश मालवेअर आणि फिशिंगसाठी तपासा. मोफत व खाजगी विश्लेषण, स्पष्ट निकाल आणि सुरक्षित दुरुस्ती."),
    "ta": ("CyberScan: கோப்புகள், இணைப்புகளை இலவசமாக சோதிக்கவும்",
           "திறப்பதற்கு முன் எந்தக் கோப்பு, இணைப்பு அல்லது செய்தியையும் தீம்பொருள், ஃபிஷிங்கிற்காகச் சோதிக்கவும். இலவச, தனிப்பட்ட பகுப்பாய்வு, தெளிவான முடிவு."),
    "te": ("CyberScan: ఫైళ్లు, లింక్‌లను ఉచితంగా తనిఖీ చేయండి",
           "తెరవడానికి ముందు ఏ ఫైల్, లింక్ లేదా సందేశాన్నైనా మాల్వేర్, ఫిషింగ్ కోసం తనిఖీ చేయండి. ఉచిత, ప్రైవేట్ విశ్లేషణ, స్పష్టమైన ఫలితం."),
    "id": ("CyberScan: pindai file dan tautan gratis",
           "Periksa file, tautan, atau pesan apa pun dari malware dan phishing sebelum dibuka. Analisis gratis dan privat, hasil jelas, dan perbaikan aman."),
    "ms": ("CyberScan: imbas fail dan pautan secara percuma",
           "Semak sebarang fail, pautan atau mesej untuk perisian hasad dan pancingan data sebelum dibuka. Analisis percuma dan peribadi, keputusan jelas."),
    "fil": ("CyberScan: libreng pag-scan ng file at link",
            "Suriin ang anumang file, link o mensahe para sa malware at phishing bago ito buksan. Libre at pribadong pagsusuri, malinaw na resulta at ligtas na pag-aayos."),
    "vi": ("CyberScan: quét tệp và liên kết miễn phí",
           "Kiểm tra mọi tệp, liên kết hay tin nhắn để phát hiện mã độc và lừa đảo trước khi mở. Phân tích miễn phí, riêng tư, kết luận rõ ràng và sửa chữa an toàn."),
    "th": ("CyberScan: สแกนไฟล์และลิงก์ฟรี",
           "ตรวจไฟล์ ลิงก์ หรือข้อความใด ๆ หามัลแวร์และฟิชชิงก่อนเปิด วิเคราะห์ฟรีและเป็นส่วนตัว ผลลัพธ์ชัดเจน และซ่อมแซมอย่างปลอดภัย"),
    "zh": ("CyberScan：免费扫描文件和链接",
           "在打开之前检查任何文件、链接或消息中的恶意软件和网络钓鱼。免费、私密的分析，结论清晰，安全修复。"),
    "ja": ("CyberScan：ファイルとリンクを無料でスキャン",
           "開く前にファイル、リンク、メッセージのマルウェアやフィッシングをチェック。無料でプライベートな分析、わかりやすい判定と安全な修復。"),
    "ko": ("CyberScan: 파일과 링크 무료 검사",
           "열기 전에 모든 파일, 링크, 메시지의 악성코드와 피싱을 확인하세요. 무료 비공개 분석, 명확한 결과와 안전한 복구."),
    "sw": ("CyberScan: kagua faili na viungo bure",
           "Kagua faili, kiungo au ujumbe wowote dhidi ya programu hasidi na hadaa kabla ya kuufungua. Uchambuzi wa bure na wa faragha, matokeo wazi."),
}

# ---------------------------------------------------------------- other pages: English + Arabic
PAGES = {
    "/app.html": {
        "en": ("Scan a file, link or message · CyberScan",
               "Drop a file or paste a link or message: CyberScan checks it for malware and phishing without running it, and explains the result in plain words."),
        "ar": ("افحص ملفًا أو رابطًا أو رسالة · CyberScan",
               "أفلت ملفًا أو الصق رابطًا أو رسالة: يفحصها CyberScan بحثًا عن البرمجيات الخبيثة والتصيّد دون تشغيلها، ويشرح النتيجة بلغة بسيطة."),
    },
    "/journey": {
        "en": ("The File Journey: how a file is scanned · CyberScan",
               "Dive into a file and follow CyberScan from the first byte to the verdict: structure, analysis, intelligence and verification, in one continuous 3D journey."),
        "ar": ("رحلة الملف: كيف يُفحص الملف · CyberScan",
               "ادخل إلى الملف وتابع CyberScan من أول بايت حتى الحكم: البنية والتحليل والمعلومات الاستخبارية والتحقق، في رحلة ثلاثية الأبعاد متصلة."),
    },
    "/support": {
        "en": ("Support the developer · CyberScan",
               "Support the developer behind CyberScan, see the research and projects, and explore the Cubeverse: six interactive worlds of cubes."),
        "ar": ("ادعم المطوّر · CyberScan",
               "ادعم مطوّر CyberScan، واطّلع على الأبحاث والمشاريع، واستكشف عالم المكعبات: ستة عوالم تفاعلية."),
    },
    "/privacy": {
        "en": ("Privacy policy · CyberScan", "What CyberScan reads, what it keeps (nothing about you), the one cookie it sets and the services it relies on."),
        "ar": ("سياسة الخصوصية · CyberScan", "ما الذي يقرؤه CyberScan، وما الذي يحتفظ به (لا شيء عنك)، وملف تعريف الارتباط الوحيد، والخدمات التي يعتمد عليها."),
    },
    "/terms": {
        "en": ("Terms of use · CyberScan", "The terms for using CyberScan: a static analysis service that explains what it finds and never runs your files."),
        "ar": ("شروط الاستخدام · CyberScan", "شروط استخدام CyberScan: خدمة تحليل ساكن تشرح ما تجده ولا تشغّل ملفاتك أبدًا."),
    },
    "/security": {
        "en": ("Security & vulnerability disclosure · CyberScan", "How to report a security issue in CyberScan, what we promise in return and how we handle reports."),
        "ar": ("الأمان والإبلاغ عن الثغرات · CyberScan", "كيف تبلغ عن مشكلة أمنية في CyberScan، وما نلتزم به في المقابل، وكيف نتعامل مع البلاغات."),
    },
    "/status": {
        "en": ("System status · CyberScan", "Live status of the CyberScan engine: threat rules, known-malware fingerprints, link lists and when they were last updated."),
        "ar": ("حالة النظام · CyberScan", "الحالة المباشرة لمحرك CyberScan: قواعد التهديد، وبصمات البرمجيات الخبيثة، وقوائم الروابط، وآخر تحديث لها."),
    },
    "/tests": {
        "en": ("Independent tests: measured, not promised · CyberScan", "How CyberScan is tested and the measured numbers: false alarms on clean files, attack-shaped samples and speed."),
        "ar": ("اختبارات مستقلة: أرقام مقيسة لا وعود · CyberScan", "كيف يُختبر CyberScan والأرقام المقيسة: الإنذارات الكاذبة على الملفات النظيفة، والعيّنات الهجومية، والسرعة."),
    },
    "/changelog": {
        "en": ("What's new · CyberScan", "Every CyberScan release, with dates: new detection, repair, apps and site features."),
        "ar": ("ما الجديد · CyberScan", "كل إصدارات CyberScan بتواريخها: كشف جديد وإصلاح وتطبيقات وميزات للموقع."),
    },
}
# the language a page is written in when its address has no language prefix
DEFAULT_LANG = {"/support": "ar"}
CRUMB = {"/app.html": ("Scan", "الفحص"), "/journey": ("The File Journey", "رحلة الملف"), "/support": ("Support the developer", "ادعم المطوّر"),
         "/privacy": ("Privacy", "الخصوصية"), "/terms": ("Terms", "الشروط"), "/security": ("Security", "الأمان"),
         "/status": ("Status", "حالة النظام"), "/tests": ("Independent tests", "الاختبارات المستقلة"), "/changelog": ("What's new", "ما الجديد")}

ICONS = ('<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">',
         '<link rel="icon" type="image/png" sizes="48x48" href="/favicon-48.png">',
         '<link rel="icon" type="image/png" sizes="96x96" href="/favicon-96.png">',
         '<link rel="icon" type="image/png" sizes="192x192" href="/favicon-192.png">',
         '<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">')


def text_for(path: str, lang: str | None) -> tuple[str, str] | None:
    table = HOME if path == "/" else PAGES.get(path)
    if not table:
        return None
    code = lang or DEFAULT_LANG.get(path, "en")
    return table.get(code) or table["en"]


def _ld(obj: dict) -> str:
    return '<script type="application/ld+json">' + json.dumps(obj, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/") + "</script>"


def site_ld(path: str, lang: str | None, url: str) -> str:
    """WebSite + Organization on the home page (Google uses them for the site name and logo in
    results); a BreadcrumbList on the other pages."""
    if path == "/":
        return _ld({"@context": "https://schema.org", "@graph": [
            {"@type": "WebSite", "@id": f"{SITE}/#website", "url": f"{SITE}/", "name": "CyberScan",
             "alternateName": ["سايبر سكان", "CyberScan Scanner"], "inLanguage": lang or "en",
             "publisher": {"@id": f"{SITE}/#org"}},
            {"@type": "Organization", "@id": f"{SITE}/#org", "name": "CyberScan", "url": f"{SITE}/",
             "logo": {"@type": "ImageObject", "url": f"{SITE}/icon-512.png", "width": 512, "height": 512},
             "description": HOME["en"][1]},
        ]})
    if path in CRUMB:
        en, ar = CRUMB[path]
        home = f"{SITE}/{lang}/" if lang else f"{SITE}/"
        return _ld({"@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": [
            {"@type": "ListItem", "position": 1, "name": "CyberScan", "item": home},
            {"@type": "ListItem", "position": 2, "name": ar if (lang or DEFAULT_LANG.get(path)) == "ar" else en, "item": url}]})
    return ""


def apply(page: str, path: str, lang: str | None, url: str | None) -> tuple[str, list[str]]:
    """Return the page with its title/description set and the head pieces to add."""
    add: list[str] = []
    found = text_for(path, lang)
    if found:
        title, desc = (html.escape(found[0], quote=True), html.escape(found[1], quote=True))
        page = re.sub(r"<title>.*?</title>", lambda m: f"<title>{title}</title>", page, count=1, flags=re.S)
        page = re.sub(r'\s*<meta (?:name="description"|property="og:(?:title|description|site_name|type|locale)"|name="twitter:(?:title|description)")[^>]*>', "", page)
        add += [f'<meta name="description" content="{desc}">',
                f'<meta property="og:title" content="{title}">', f'<meta property="og:description" content="{desc}">',
                '<meta property="og:site_name" content="CyberScan">', '<meta property="og:type" content="website">',
                f'<meta name="twitter:title" content="{title}">', f'<meta name="twitter:description" content="{desc}">']
    page = re.sub(r'\s*<link rel="(?:icon|shortcut icon|apple-touch-icon)"[^>]*>', "", page)
    add += list(ICONS)
    if url:
        ld = site_ld(path, lang, url)
        if ld:
            add.append(ld)
    return page, add
