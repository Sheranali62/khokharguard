KhokharGuard YARA starter rules
=============================

Location: signatures/yara/*.yar (and *.yara)
Loaded by: engine/yara_engine.py (requires optional yara-python;
           the app works fully without it - spec section 18)

Starter set (all rules are safe, content-based, and developed
in-house - no third-party rules and no malware samples are bundled):

  suspicious_scripts.yar
      Download cradles, obfuscated base64 execution, scheduled-task
      persistence, mshta remote execution.

  shortcut_abuse.yar
      .lnk shortcuts launching interpreters or hidden windows,
      .url internet shortcuts pointing at local executables.

  autorun_abuse.yar
      autorun.inf configurations that auto-open scripts/interpreters
      or hidden executables from removable drives.

Severity policy
---------------
  "high"   - pattern is essentially always malicious; YARA matches
             force the risk score to 100 (engine/file_analyzer.py).
  "medium" - strong indicator that legitimate software occasionally
             uses; forces score to 70 = SUSPICIOUS band. KhokharGuard
             classifies these for user review - never auto-deleted.

Rule authoring
--------------
  - One condition per rule; keep `filesize < N` guards so YARA never
    scans multi-gigabyte files needlessly.
  - Set meta.severity, meta.category, and meta.description - the
    engine reads them for the detection verdict.
  - Validate after editing: the About page self-test, or
      python -c "from engine.yara_engine import YaraEngine; \
                 print(YaraEngine().validate_rules())"
    (empty list = all rule files valid).
  - Rules are recompiled at every application start and never
    downloaded at runtime; signature updates land here only via the
    verified update flow (spec section 37).
