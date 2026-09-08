---
title: NLTK Corpus Reader Path Traversal via Symlink Bypass
slug: 2026-09-nltk-path-traversal
description: NLTK corpus readers in versions 3.10.2 and earlier fail to enforce path security boundaries when processing symlinks, allowing attackers to disclose files outside of the trusted corpus root.
date: "2026-09-08T20:05:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nltk:nltk:*:*:*:*:*:*:*:*
vendors:
  - NLTK Project
products:
  - NLTK (<= 3.10.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: An attacker who can stage corpus files or symlinks under a trusted data root can disclose outside-root content through normal corpus-reader results.
    confidence_band: high
cves:
  - id: CVE-2026-79676
    cvss: 5.9
    epss: 0.00307
references:
  - https://github.com/advisories/GHSA-p4rw-rvv2-7xwr
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79676
action_plan:
  priority: elevated
  owners:
    - Development Team
    - Security Operations
  immediate_actions:
    - action: Update NLTK to 3.10.3 or later
      owner: Development Team
      due: 48h
      evidence: Source explicitly identifies vulnerability in NLTK <= 3.10.2
  mitigation_plan:
    - priority: immediate
      action: Remove system temporary directories from NLTK allowed-roots configuration.
      owner: Security Operations
      addresses: Global sandbox fallback vulnerability
      evidence: Source states global-sandbox fallback is only as tight as the allowed-roots list.
---

NLTK (Natural Language Toolkit) versions up to and including 3.10.2 are vulnerable to a path traversal and symlink boundary bypass (CVE-2026-79676). The vulnerability exists because several corpus readers - including `IPIPANCorpusReader`, `CrubadanCorpusReader`, and `LinThesaurusCorpusReader` - derive file paths from the corpus state and subsequently reopen them using the standard built-in `open()` function instead of the secure `nltk.pathsec.open()` wrapper.

When `pathsec.ENFORCE=True` is enabled, NLTK is intended to restrict file access to trusted directories. However, because these specific readers do not preserve the trusted-root boundary during file access, a symlink placed inside a trusted corpus root can be used to traverse and access arbitrary files on the underlying filesystem. This allows an attacker to disclose sensitive outside-root content through standard public corpus-reader methods such as `synonyms()` or `categories()`. This issue affects multiple components across the NLTK codebase, including `MTEFileReader` and various XML-based corpus parsers.

## Impact

Successful exploitation allows for unauthorized disclosure of arbitrary files on the filesystem where the NLTK library is processing corpus data. This poses a significant security risk in shared, multi-user, or automated environments where NLTK processes untrusted or attacker-influenced corpus data. The impact is limited to information disclosure and does not include write access or arbitrary code execution; however, it effectively bypasses intended sandbox protections designed to secure NLTK-based applications.

## Recommendation

Prioritized actions for development and security teams:

* Update the NLTK library to a patched version once released, or apply manual remediation by wrapping all raw `open()` calls within affected corpus readers using `nltk.pathsec.validate_path(path, required_root=...)` or `nltk.pathsec.open()`.
* Audit corpus-processing pipelines to ensure they do not rely on the inclusion of the system temporary directory within the `pathsec` allowed-roots configuration.
* Implement strict filesystem permissions on directories used as NLTK trusted corpus roots to prevent unauthorized creation of symlinks by untrusted users.
* Deploy internal monitoring to detect unexpected file access patterns originating from the NLTK process, particularly targeting sensitive system files or configuration paths.
