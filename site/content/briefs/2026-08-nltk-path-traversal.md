---
title: Arbitrary File Read in NLTK via Path Traversal
slug: 2026-08-nltk-path-traversal
description: NLTK versions prior to 3.10.0 are vulnerable to path traversal (CVE-2026-12243) due to improper sequence decoding in nltk.data.load(), allowing attackers to read arbitrary files.
date: "2026-08-14T02:03:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nltk:nltk:3.9.4:*:*:*:*:*:*:*
products:
  - nltk
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1006
    technique_name: File System Logical Offset
    evidence: An attacker supplying %2e%2e instead of .. bypasses all path validation and reads arbitrary files outside the NLTK data directory.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This affects any application that passes user-controlled input to nltk.data.load() or nltk.data.find().
    confidence_band: high
cves:
  - id: CVE-2026-12243
    cvss: 7.5
    epss: 0.00583
references:
  - https://github.com/advisories/GHSA-m42h-3232-vpv3
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Patch nltk to 3.10.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-12243
  mitigation_plan:
    - priority: immediate
      action: Validate all user-supplied paths passed to NLTK functions
      owner: AppSec
      addresses: CVE-2026-12243
      evidence: Application code audit required
---

NLTK (Natural Language Toolkit) versions prior to 3.10.0 contain a critical path traversal vulnerability (CVE-2026-12243) in the `nltk.data.load()` and `nltk.data.find()` functions. The vulnerability exists because the library performs security validation checks on a user-supplied `resource_name` string before decoding percent-encoded sequences using `url2pathname()`. 

An attacker can bypass these safety checks by supplying encoded traversal sequences (e.g., `%2e%2e` instead of `..`). Because the security validation logic operates on the encoded input, the malicious path is permitted. Once the internal validation is cleared, `url2pathname()` decodes the sequence to `..`, enabling the function to resolve paths outside of the intended NLTK data directory. This allows an attacker to read any file on the filesystem accessible by the application process, including sensitive credentials, configuration files, and SSH keys.

## Impact

Successful exploitation allows unauthorized access to sensitive system files. In environments where an application exposes functionality that accepts user-defined resource paths to the NLTK library (such as an NLTK-based web scraper or NLP analysis service), an unauthenticated or low-privileged attacker can exfiltrate arbitrary files. This may lead to credential theft, full server compromise, or unauthorized access to protected application data.

## Recommendation

- Upgrade the `nltk` library to version 3.10.0 or later immediately to patch CVE-2026-12243.
- Audit applications using `nltk.data.load()` or `nltk.data.find()` to determine if user-controlled input is passed directly to these functions without external sanitization.
- If upgrading is not immediately possible, implement a wrapper around `nltk.data.load()` that manually performs URL decoding (`urllib.parse.unquote`) on the input path before any other processing or validation occurs.
