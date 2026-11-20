# CyberScan — project knowledge for the "Ask the AI" assistant

This document is the assistant's only source of facts about CyberScan. Every statement here was
checked against the source code (file references in brackets). If a question is not answered here,
the honest answer is "this isn't covered in what I know about CyberScan".

## 1. What CyberScan is, in plain words

CyberScan checks files, links and pieces of text for warning signs **without ever running them**.
It reads a file the way you would read a document: as data. It measures how the bytes are
arranged, what the file claims to be, what a program says it can do, and whether known tricks or
known threats appear. Then it explains what it found in everyday language, in the visitor's
language, with the technical evidence underneath.

It is a defensive research and education project built by the ONYX team,
published at https://ainex-ai.xyz (ainex-ai.xyz is the website's address). It is not a replacement for commercial antivirus or endpoint
protection, and it says so.

Where it runs:
- **Desktop app** (Windows, Python + PySide6): scans on the user's own computer. Keeps a local
  history (last 200 scans). Optional local AI summary through Ollama. Optional Downloads-folder
  watch. Encrypted quarantine and blind repair.
- **Android app** (signed APK): the analysis engine runs on the phone itself (Python compiled to
  WebAssembly with Pyodide).
- **Website** (ainex-ai.xyz, scan page at scan.ainex-ai.xyz): a file you check is uploaded to
  CyberScan's server (AWS Lambda), read in memory and deleted when the check ends; no shared
  history is kept on the server, results stay in the visitor's browser. Uploads are limited to
  about 6 MB on the website. No local AI, quarantine, or path scanning on the public server.
  [web_v/server.py, public mode]

## 2. What it never does / honest limits

- It never executes, opens or "detonates" the file. There is no sandbox and no dynamic analysis,
  so it cannot see what a program does only at run time.
- A clean result is called "no warning signs observed", never "safe". A score of 0 means no
  indicators were observed, not proven safety.
- The score is an explainable heuristic indicator from 0 to 100, **not a probability** of malware.
- There is no validated claim of 98% accuracy, zero false positives, or zero-day detection.
  [README: Evaluation claims]
- Encrypted or compressed content cannot be read inside without its key or decompression.
- Code-graph analysis covers x86 / x86-64 machine code only; .NET (IL) and other architectures
  are skipped, and packed or obfuscated code can make it incomplete.
- The machine-learning classifier is off unless an operator installs a reviewed model they approve
  by its SHA-256 fingerprint; none ships by default.

## 3. How a scan works (the pipeline)

1. **Read.** The bytes are read once into memory, up to a size limit (50 MiB by default in the
   desktop app). SHA-256/SHA-1/MD5 fingerprints are computed. [core/hashing.py]
2. **Identify.** Magic bytes reveal the real file type; a mismatch with the extension (for example
   a program named `invoice.pdf.exe`) is a strong warning sign ("Header mismatch", +25).
   [core/magic_bytes.py, core/file_analyzer.py]
3. **Measure** (the science, sections 4–8 below): entropy topography, positional surprise,
   program structure, control-flow graph, claim-versus-capability dissonance.
4. **Compare.** Heuristic rules (suspicious strings, encoded PowerShell, shadow-copy deletion…),
   YARA rules (including the open YARA-Forge rule sets when installed), local threat lists
   (URLhaus malware links, Phishing.Database), secret-leak patterns (gitleaks), lookalike-domain
   checks (punycode, brand names in the wrong domain), MITRE ATT&CK mapping. [core/heuristic_engine.py,
   core/yara_engine.py, core/protection.py, core/mitre_mapper.py]
5. **Optional online lookups** (off by default; section 10).
6. **Explain.** Each finding has a category, severity, a sentence a person can check, and a
   contribution from 0 to 100. The verdict score is the **largest** contribution (not the sum).
   Bands: 0 = no indicators observed; 1–49 = review; 50 or more = suspicious. [core/risk_engine.py]

## 4. Entropy topography (how "random" each part of the file is)

Plain words: entropy measures how unpredictable bytes are. Text and code repeat patterns (medium
entropy); empty padding is all the same (zero); encrypted or compressed data looks like noise (close
to the maximum). A sudden jump from ordinary content to noise often marks where something hidden or
encoded starts.

Technical: Shannon information entropy per window, H = −Σ p(x)·log2 p(x), computed in the code as
H = log2 n − (1/n)·Σ c·log2 c over byte counts c, in bits per byte (0 to 8). The window slides
through the file (128-byte windows every 32 bytes for small inputs; the file scan uses 4096-byte
windows every 1024 bytes). Counts are updated incrementally. A **discontinuity** is recorded when
adjacent windows differ by at least 1.5 bits, or the curve jumps from below 3.5 to above 7.2.
Severity: medium; high if the jump is ≥ 2.0; critical if ≥ 3.0. Findings: "High entropy" (+18)
when a window exceeds 7.0 bits/byte (not for naturally compressed formats such as images, video,
PDF, ZIP, or signed programs); "Entropy discontinuity" (+12). Mapped to ATT&CK T1027 (Obfuscated
Files or Information). Note: a 128-byte window can never exceed log2(128) = 7 bits.
The project calls this "thermodynamic entropy topography", but it is information entropy, not the
physical (thermodynamic) quantity. [core/entropy.py, core/nextgen_engine.py]

## 5. Positional surprise (same bytes, different meaning depending on where they are)

Plain words: random-looking data inside a program's resources (pictures, icons) is normal; the same
data inside its code section is not. CyberScan learned what honest programs normally contain in
each part (header, code, data, resources, overlay) and flags windows that don't fit their part.

Technical: for each 4 KiB window, the Kullback–Leibler divergence D_KL(P‖Q) = Σ p·log2(p/q) between
the window's byte distribution P and a benign distribution Q for that part (Laplace-smoothed). A
window is "foreign" if it exceeds the benign 99.9th percentile for its part and at least 0.75 bits
per byte. The profile was fitted on 1,500 benign Windows programs and is loaded only if its SHA-256
matches. Programs only (PE files). [core/surprise_map.py]

## 6. Program structure (PE analysis)

For Windows programs, the PE format is parsed with `pefile`: sections and their flags (writable,
executable), section entropy (> 7.0 = high-entropy section), the import table (which system
functions the program uses), the version resource (what it claims to be), and the Authenticode
digital signature. Suspicious imports such as VirtualAlloc, WriteProcessMemory, CreateRemoteThread
(process-injection building blocks) raise the score and map to ATT&CK T1055. A program whose
signature is valid is judged on strong evidence only. [core/pe_decompiler.py, core/authenticode.py]

## 7. Control-flow graph, CFG (the shape of the code, disassembly)

Plain words: CyberScan decodes the program's machine instructions (without running them) and draws
how the code can jump around: straight runs of instructions ("basic blocks") connected by branches
and loops. Certain loop shapes are typical of code that decrypts a hidden payload in place.

Technical: Capstone disassembler, linear sweep, up to 256 KiB of the entry-point code section,
architecture taken from the PE header. A new basic block starts at the first instruction, at any
branch target, and after any branch, call or return. Edges connect a block to its branch target and
to the following block. Cyclomatic complexity M = E − N + 2P (edges, blocks, connected
components). A back edge (to an earlier block) is a loop. The only pattern that warns is strict:
INPLACE_XOR_DECODER_LOOP — a short loop (≤ 48 instructions) that XORs into memory while stepping a
counter, and in a program it also needs somewhere to decrypt into (a writable+executable or
high-entropy non-resource section). Finding: "Static decoding indicator" (+15), ATT&CK T1027.
Looser "descriptive" patterns are recorded but never warn, because in a measurement they matched
93% of 400 benign Windows programs (compilers zero registers with `xor eax, eax`). Skipped for .NET
and non-x86 code. [core/nextgen_engine.py, core/pe_decompiler.py]

## 8. Claim versus capability (dissonance)

Plain words: malware lies about what it is. A "photo viewer" has no business recording the
keyboard. CyberScan compares what a program claims to be (name, description) with what its imports
say it can do.

Technical: the claim is reduced to a role (media viewer, installer, game, security tool…). For
each observed capability, surprise = −log2 p(capability | role) bits, weighted by potential harm.
Probabilities start from an expert prior (worth 20 programs per role) and are refined on benign
programs only. Explicit lies (a program dressed as a document, an unsigned copy of a Windows process
name) are scored separately. [core/dissonance.py]

## 9. The 4096-dimensional representation and the classifier

Plain words: all the measurements are packed into one long list of 4,096 numbers, a fingerprint of
the file's structure, so that a learning model could compare files. It is a fixed recipe, not a
neural network.

Technical: four channels of 1,024 numbers: (0) byte histogram plus hashed 2/3/4-byte n-grams and
opcode frequencies; (1) entropy trajectory and gradients, resampled to 512 + 512; (2) graph metrics,
block out-degrees, hashed edges and patterns; (3) PE header values, section sizes, hashed import
names. Variable-size features are placed by feature hashing (a BLAKE2b digest of the feature name
chooses the coordinate). Each channel is scaled to unit length, then the whole vector. It is lossy
and deterministic. A random-forest classifier (classes: clean, suspicious, malware) with conformal
abstention can read it, but only when an operator installs a reviewed model approved by SHA-256; no
model ships, so by default scans use static evidence only. Its scores are uncalibrated and its
weight in the verdict defaults to zero. CyberScan does not run similarity searches over these
vectors. [core/deep_embedding.py, ml/structural_classifier.py, ml/conformal.py]

## 10. Online threat intelligence (OSINT)

Off by default. When enabled, only the file's SHA-256 fingerprint (or the link) is sent, never the
file. Three public services are queried at the same time (asyncio): abuse.ch ThreatFox, abuse.ch
URLhaus, and AlienVault OTX (URLhaus and OTX need API keys). Fast feeds get a 450 ms budget and a
shared deadline cancels slow ones. Answers are normalized to one record format and cached for 5
minutes. Overall status: any match → matched; all unavailable → unavailable; any timeout →
partial_timeout; otherwise no_match. A match adds "External threat-intelligence match" (+70): a
report, not proof. No match is not proof of safety. [core/global_intelligence.py]

## 11. Repair and quarantine

**Blind repair** finds parts that don't belong in a file's format (for example data hidden after
the end of a file, active content in a PDF, a disguised double extension), removes them from a
**copy**, and checks that the copy still opens as the same type of file with its structure intact.
The original is never modified, and removed parts are sealed in the encrypted vault. It does not
"disinfect" arbitrary malware inside a program's code. [repair_engine/]

**Encrypted quarantine** (desktop app) seals a suspicious file with AES-GCM under a key protected by
the user's Windows account; it can be restored. Nothing is deleted unencrypted.

## 12. Privacy

- Desktop and Android apps: scanning happens on the device. By default nothing is sent to the
  internet (online lookups are opt-in).
- Website: the file is sent to CyberScan's server for the check, read in memory, and deleted when
  the check ends; no shared history is kept on the server.
- The optional AI summary in the desktop app runs locally through Ollama and receives only
  structured facts, never the file name, path or content.
- This assistant ("Ask the AI") receives only the question typed into it, never scanned files.

## 13. Languages and accessibility

The interface supports 30 languages including Arabic, Urdu and Persian with right-to-left layout.
There are reduced-motion and light (performance) modes.

## 14. How to read a result and its score (for non-experts)

- **No warning signs observed (score 0):** none of the checks found an indicator. Not a guarantee.
- **Review (1–49):** something is worth a closer look; read the findings.
- **Suspicious (50+):** strong warning signs; don't open it unless you trust the source.
- Each finding says what was seen and why it matters. The strongest finding sets the score.
- Advice: if a file is unexpected, from an unknown sender, or named like a document but is really a
  program, don't run it.

## 15. Glossary

- **Static analysis:** examining a file without running it.
- **Entropy:** how unpredictable the bytes are (0–8 bits per byte).
- **PE file:** the Windows program format (.exe, .dll).
- **Import:** a system function a program says it will use.
- **Basic block / CFG:** a straight run of instructions / the graph of jumps between them.
- **Hash (SHA-256):** a fingerprint of a file; any change gives a different fingerprint.
- **YARA rule:** a pattern description used by researchers to recognize known malware families.
- **MITRE ATT&CK:** a public catalogue of attacker techniques (e.g. T1027 obfuscation, T1055
  process injection).
- **OSINT:** open-source intelligence, here public threat-report services.
- **False positive:** a warning on something harmless. Heuristics can produce them; that is why
  every finding is explained.

## 16. Arabic quick answers (أجوبة سريعة بالعربية)

- **ما هو CyberScan؟** أداة تفحص الملفات والروابط والنصوص بحثًا عن علامات التحذير **دون تشغيلها أبدًا**،
  وتشرح ما تجده بكلمات بسيطة. مشروع بحثي تعليمي دفاعي بناه فريق ONYX، ومنشور على الموقع ainex-ai.xyz، وليس بديلًا لبرامج مكافحة الفيروسات التجارية.
- **هل يشغّل الملف؟** لا. التحليل ساكن فقط: يقرأ البايتات كبيانات.
- **هل النتيجة النظيفة تعني أن الملف آمن؟** لا. تعني "لم تُرصد علامات تحذير"، وليست ضمانًا.
- **ماذا تعني الدرجة؟** مؤشر قابل للشرح من 0 إلى 100 وليس احتمالًا. 0 لا مؤشرات، 1–49 مراجعة، 50 فأكثر مشبوه.
  الدرجة تساوي أقوى دليل منفرد وليست مجموع الأدلة.
- **الإنتروبيا؟** مقياس لعشوائية البايتات (0–8 بت لكل بايت). البيانات المشفّرة أو المضغوطة قريبة من 8،
  والقفزة المفاجئة قد تدل على بداية جزء مخفي. هي إنتروبيا شانون المعلوماتية وليست الإنتروبيا الفيزيائية.
- **مخطط تدفق التحكم؟** رسم لكيفية قفز تعليمات البرنامج بين أجزائه، يُستخرج دون تشغيل. حلقة XOR تكتب في
  الذاكرة قد تدل على فك تشفير حمولة مخفية.
- **المتجه ذو 4096 بُعدًا؟** بصمة رقمية ثابتة لبنية الملف من أربع قنوات، وليست شبكة عصبية. المصنّف الذي
  يقرؤها معطّل افتراضيًا.
- **أين يُفحص الملف؟** في تطبيقي سطح المكتب وأندرويد على جهازك. في الموقع يُرسل إلى خادم CyberScan،
  ويُقرأ في الذاكرة ثم يُحذف عند انتهاء الفحص.
- **البحث في مصادر التهديدات؟** معطّل افتراضيًا، وعند تفعيله تُرسل البصمة (SHA-256) فقط وليس الملف.
- **الإصلاح الأعمى؟** يزيل من **نسخة** الملف الأجزاء التي لا تنتمي إلى صيغته ويتحقق أنها ما زالت تُفتح،
  ولا يمسّ الأصل.

## 17. Quick answers (English)

- **What does CyberScan do, in simple words?** It checks files, links and text for warning signs
  without ever running them, then explains what it found in plain language. It is a defensive
  research and education project, not a replacement for commercial antivirus.
- **Does it run my file?** No. Never. It only reads the file's bytes as data (static analysis):
  nothing is opened, executed or "detonated", so it cannot see behaviour that only happens at run time.
- **What is entropy and why does it matter?** Entropy measures how unpredictable a file's bytes
  are, from 0 to 8 bits per byte. Encrypted or compressed data is close to 8; a sudden jump from
  ordinary content to that level can mark where something packed or hidden begins.
- **What does a score of 30 mean?** "Review": something is worth a closer look. The score is the
  strongest single warning (0 = no indicators observed, 1–49 = review, 50+ = suspicious). It is
  an explainable indicator, not a probability of malware. Read the findings to see why.
- **Where is my file checked on this website?** On the website, the file is sent to CyberScan's
  server, read in memory and deleted when the check ends; no history is kept there. The desktop
  and Android apps check files on your own device instead.
- **Is a clean result a guarantee?** No. It means "no warning signs observed", not "safe".
- **Does it use AI?** The scan itself uses measurements and rules, not a chatbot. An optional
  classifier exists but is off by default. The desktop app can write a plain-language summary with
  a local AI model. This assistant answers questions about the project from a reviewed guide.
