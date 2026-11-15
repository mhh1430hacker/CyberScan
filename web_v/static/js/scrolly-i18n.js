/* Text for the scroll story at the top of #science, English and Arabic. The English strings are
 * also written in index.html (data-i18n), so the story reads without JavaScript. Other languages
 * fall back to English. */
"use strict";
(function () {
  const I = window.I18N;
  if (!I) return;
  Object.assign(I.en, {
    sciTag: "// The science", sciTitle: "The science behind CyberScan", sciSub: "Scroll to see how CyberScan works.",
    sciDeepTitle: "The technical deep dive",
    sciDeepNote: "The engine step by step, with its maths and real output on a harmless demo file. This part is in English.",
    sciDeepShow: "Show the full technical detail", sciDeepHide: "Hide the technical detail",
    syNav: "Story chapters",
    syK1: "The digital world", syK2: "Inside a file", syK3: "How CyberScan analyzes", syK4: "Beyond files", syK5: "One ecosystem", syK6: "CyberScan",
    syT1: "Everything is connected.", syT2: "A name is only a label.", syT3: "Six steps. Nothing runs.", syT4: "Threats don't only hide in files.", syT5: "Many checks. One clear answer.", syT6: "See beyond the surface.",
    sy1b0: "Files, apps, websites and devices talk to each other all day.", sy1b1: "Almost everything that moves between them is safe.", sy1b2: "But a threat can look exactly like everything else.",
    syYou: "You", syFiles: "Files", syApps: "Apps", syWeb: "Websites", syDevices: "Devices", syNet: "Networks", syCloud: "Cloud", syLooks: "Looks normal",
    sy2b0: "This file says it is an invoice.", sy2b1: "CyberScan looks inside it, layer by layer.", sy2b2: "The name says document. The inside says program.",
    syL1: "Name", syL1d: "What it claims to be", syL2: "First bytes", syL2d: "What it really is: a program", syL3: "Structure", syL3d: "How it is built",
    syL4: "Contents", syL4d: "Ordered, or scrambled?", syL5: "Fingerprint", syL5d: "A unique ID for these exact bytes",
    syS1: "Receive", syS1d: "The file arrives. It is never opened or run.", syS2: "Structure", syS2d: "Its real format and parts are read.",
    syS3: "Indicators", syS3d: "Clues are collected: name, signature, scrambled data, known patterns.", syS4: "Weigh", syS4d: "Each clue is weighed: harmless alone, or a real warning sign?",
    syS5: "Combine", syS5d: "Clues about the same thing count once. The strongest decides.", syS6: "Assess", syS6d: "A score and a plain explanation.",
    syRes: "Suspicious", syResWhy: "A program pretending to be a document. A warning sign, not proof.", syResNote: "Real result from CyberScan's engine on a harmless test file.",
    sy4b0: "Danger also travels in links, emails and websites.", sy4b1: "It hides in networks, systems, code and the cloud.", sy4b2: "Solid: on the website today. Dashed: being built.",
    syD1: "File security", syD2: "Malware analysis", syD3: "URL & domain", syD4: "Website security", syD5: "Email security",
    syD6: "Network security", syD7: "System security", syD8: "Privacy", syD9: "Code & dependencies", syD10: "Cloud & infrastructure",
    sy5b0: "Each area needs its own checks.", sy5b1: "CyberScan connects them: a link inside an email, the download behind a link, a secret inside code.",
    sy5b2: "The aim: one clear answer you can understand, wherever the risk comes from.",
    sy6s: "CyberScan reads what things really are, explains it in plain words, and is honest about what it cannot know.",
    syCtaScan: "Scan something now", syCtaAsk: "Ask the AI",
  });
  Object.assign(I.ar, {
    sciTag: "// العلم", sciTitle: "العلم وراء CyberScan", sciSub: "مرّر لترى كيف يعمل CyberScan.",
    sciDeepTitle: "الشرح التقني المفصّل",
    sciDeepNote: "المحرّك خطوة بخطوة، مع رياضياته ومخرجاته الحقيقية على ملف تجريبي غير ضار. هذا الجزء باللغة الإنجليزية.",
    sciDeepShow: "اعرض التفاصيل التقنية كاملة", sciDeepHide: "أخفِ التفاصيل التقنية",
    syNav: "فصول القصة",
    syK1: "العالم الرقمي", syK2: "داخل الملف", syK3: "كيف يحلّل CyberScan", syK4: "ما بعد الملفات", syK5: "منظومة واحدة", syK6: "CyberScan",
    syT1: "كل شيء متصل.", syT2: "الاسم مجرد ملصق.", syT3: "ست خطوات، ولا يُشغَّل شيء.", syT4: "التهديدات لا تختبئ في الملفات وحدها.", syT5: "فحوص كثيرة، وجواب واحد واضح.", syT6: "انظر إلى ما وراء السطح.",
    sy1b0: "الملفات والتطبيقات والمواقع والأجهزة تتواصل طوال اليوم.", sy1b1: "وكل ما يتنقل بينها تقريبًا آمن.", sy1b2: "لكن التهديد قد يبدو تمامًا مثل أي شيء آخر.",
    syYou: "أنت", syFiles: "الملفات", syApps: "التطبيقات", syWeb: "المواقع", syDevices: "الأجهزة", syNet: "الشبكات", syCloud: "السحابة", syLooks: "يبدو عاديًا",
    sy2b0: "هذا الملف يقول إنه فاتورة.", sy2b1: "ينظر CyberScan إلى داخله، طبقة بعد طبقة.", sy2b2: "الاسم يقول مستند، والداخل يقول برنامج.",
    syL1: "الاسم", syL1d: "ما يدّعيه", syL2: "البايتات الأولى", syL2d: "حقيقته: برنامج", syL3: "البنية", syL3d: "كيف بُني",
    syL4: "المحتوى", syL4d: "مرتّب أم مشوّش؟", syL5: "البصمة", syL5d: "معرّف فريد لهذه البايتات بالضبط",
    syS1: "الاستلام", syS1d: "يصل الملف، ولا يُفتح ولا يُشغَّل أبدًا.", syS2: "البنية", syS2d: "تُقرأ صيغته الحقيقية وأجزاؤه.",
    syS3: "المؤشرات", syS3d: "تُجمع الأدلة: الاسم، والتوقيع، والبيانات المشوّشة، والأنماط المعروفة.", syS4: "الوزن", syS4d: "يُوزن كل دليل: غير ضار بمفرده، أم علامة تحذير حقيقية؟",
    syS5: "الجمع", syS5d: "الأدلة عن الشيء نفسه تُحسب مرة واحدة، والأقوى يحسم.", syS6: "التقييم", syS6d: "درجة وشرح بكلمات بسيطة.",
    syRes: "مشبوه", syResWhy: "برنامج يتنكّر في هيئة مستند. علامة تحذير، لا دليل قاطع.", syResNote: "نتيجة حقيقية من محرّك CyberScan على ملف اختبار غير ضار.",
    sy4b0: "الخطر ينتقل أيضًا عبر الروابط والبريد والمواقع.", sy4b1: "ويختبئ في الشبكات والأنظمة والشيفرة والسحابة.", sy4b2: "الخط المتصل: متاح في الموقع اليوم. المتقطع: قيد البناء.",
    syD1: "أمان الملفات", syD2: "تحليل البرمجيات الخبيثة", syD3: "الروابط والنطاقات", syD4: "أمان المواقع", syD5: "أمان البريد",
    syD6: "أمان الشبكات", syD7: "أمان النظام", syD8: "الخصوصية", syD9: "الشيفرة والاعتماديات", syD10: "السحابة والبنية التحتية",
    sy5b0: "لكل مجال فحوصه الخاصة.", sy5b1: "يربط CyberScan بينها: رابط داخل بريد، والتنزيل خلف رابط، وسرّ داخل شيفرة.",
    sy5b2: "الهدف: جواب واحد واضح تفهمه، من أي مكان جاء الخطر.",
    sy6s: "يقرأ CyberScan حقيقة الأشياء، ويشرحها بكلمات بسيطة، ويصدُق في ما لا يستطيع معرفته.",
    syCtaScan: "افحص شيئًا الآن", syCtaAsk: "اسأل الذكاء الاصطناعي",
  });
})();
