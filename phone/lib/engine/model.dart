// CyberScan for phones: the result model shared by every check.
//
// Scoring follows the website's bands so the same evidence means the same thing everywhere:
//   0        no warning signs observed
//   1 – 49   needs review
//   50 – 100 suspicious
// The score is the strongest weighted evidence, raised a little when several independent
// signs agree. It is an explainable indicator, not a probability of malware.

enum Severity { info, low, medium, high, critical }

enum Verdict { clear, review, suspicious }

enum CheckKind { file, link, text }

class Finding {
  final String id;          // stable key, e.g. "double_extension"
  final Severity severity;
  final int weight;         // 0..100 contribution
  final String titleEn, titleAr;
  final String detailEn, detailAr;
  final String category;    // name, structure, content, program, document, archive, link, message
  const Finding({
    required this.id,
    required this.severity,
    required this.weight,
    required this.titleEn,
    required this.titleAr,
    required this.detailEn,
    required this.detailAr,
    required this.category,
  });

  String title(bool ar) => ar ? titleAr : titleEn;
  String detail(bool ar) => ar ? detailAr : detailEn;

  Map<String, dynamic> toJson() => {
        'id': id, 'severity': severity.name, 'weight': weight, 'titleEn': titleEn, 'titleAr': titleAr,
        'detailEn': detailEn, 'detailAr': detailAr, 'category': category,
      };

  static Finding fromJson(Map<String, dynamic> j) => Finding(
        id: j['id'] as String,
        severity: Severity.values.byName(j['severity'] as String),
        weight: j['weight'] as int,
        titleEn: j['titleEn'] as String,
        titleAr: j['titleAr'] as String,
        detailEn: j['detailEn'] as String,
        detailAr: j['detailAr'] as String,
        category: j['category'] as String,
      );
}

class Fact {
  final String labelEn, labelAr, value;
  const Fact(this.labelEn, this.labelAr, this.value);
  Map<String, dynamic> toJson() => {'en': labelEn, 'ar': labelAr, 'v': value};
  static Fact fromJson(Map<String, dynamic> j) => Fact(j['en'] as String, j['ar'] as String, j['v'] as String);
}

class ScanResult {
  final CheckKind kind;
  final String target;           // file name, link or the first words of the text
  final DateTime when;
  final List<Finding> findings;
  final List<Fact> facts;
  final int score;
  final Verdict verdict;
  final int elapsedMs;
  final String? sha256;
  final List<double> entropyMap;  // per-window randomness (0..8) for files

  ScanResult({
    required this.kind,
    required this.target,
    required this.when,
    required this.findings,
    required this.facts,
    required this.elapsedMs,
    this.sha256,
    this.entropyMap = const [],
  })  : score = scoreOf(findings),
        verdict = verdictOf(scoreOf(findings));

  static int scoreOf(List<Finding> findings) {
    if (findings.isEmpty) return 0;
    final weights = findings.map((f) => f.weight).where((w) => w > 0).toList()..sort((a, b) => b.compareTo(a));
    if (weights.isEmpty) return 0;
    // the strongest sign sets the floor; each further independent sign adds a little
    var score = weights.first.toDouble();
    for (final w in weights.skip(1).take(4)) {
      score += w * 0.15;
    }
    return score.round().clamp(0, 100);
  }

  static Verdict verdictOf(int score) => score == 0 ? Verdict.clear : score < 50 ? Verdict.review : Verdict.suspicious;

  List<Finding> get sorted => [...findings]..sort((a, b) => b.weight.compareTo(a.weight));

  Map<String, dynamic> toJson() => {
        'kind': kind.name, 'target': target, 'when': when.toIso8601String(), 'elapsedMs': elapsedMs, 'sha256': sha256,
        'findings': findings.map((f) => f.toJson()).toList(), 'facts': facts.map((f) => f.toJson()).toList(),
        'entropy': entropyMap,
      };

  static ScanResult fromJson(Map<String, dynamic> j) => ScanResult(
        kind: CheckKind.values.byName(j['kind'] as String),
        target: j['target'] as String,
        when: DateTime.parse(j['when'] as String),
        elapsedMs: j['elapsedMs'] as int,
        sha256: j['sha256'] as String?,
        findings: (j['findings'] as List).map((e) => Finding.fromJson(Map<String, dynamic>.from(e as Map))).toList(),
        facts: (j['facts'] as List).map((e) => Fact.fromJson(Map<String, dynamic>.from(e as Map))).toList(),
        entropyMap: ((j['entropy'] as List?) ?? const []).map((e) => (e as num).toDouble()).toList(),
      );
}

/// Small helper so every check builds findings the same way.
Finding finding(String id, Severity s, int weight, String category, String titleEn, String titleAr, String detailEn, String detailAr) =>
    Finding(id: id, severity: s, weight: weight, category: category, titleEn: titleEn, titleAr: titleAr, detailEn: detailEn, detailAr: detailAr);
