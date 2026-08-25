---
title: Remote Code Execution in NLTK AllowlistUnpickler
slug: 2026-08-nltk-rce
description: NLTK versions prior to 3.10.3 are vulnerable to remote code execution due to improper validation of dotted names during the unpickling of transition-parser models.
date: "2026-08-22T15:31:03Z"
lastmod: "2026-08-25T04:07:14Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - NLTK
products:
  - nltk
  - NLTK (3.10.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can craft untrusted transition-parser models that execute arbitrary commands when TransitionParser.parse loads the model through allowlisted_pickle_load.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: NLTK versions before 3.10.2 contain a symlink-based sandbox bypass in FramenetCorpusReader that allows attackers to read arbitrary XML files outside the corpus root.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can bypass path traversal and pickle deserialization protections by exploiting the disabled security controls that are only active when manually enabled.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Attackers can exploit bare-name binary resolution on Windows via the current working directory or on Unix-like systems via relative PATH entries to execute their binary instead of the legitimate Graphviz tool.
    confidence_band: high
cves:
  - id: CVE-2026-71513
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71513
  - https://github.com/nltk/nltk/commit/c3e37113742a1ebeeb4f2ca58941f320f98805ea
  - https://www.vulncheck.com/advisories/nltk-through-remote-code-execution-via-allowlistunpickler-dotted-name-bypass
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62384
  - https://github.com/nltk/nltk/security/advisories/GHSA-f833-7jw8-xwrv
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62388
  - https://github.com/nltk/nltk/security/advisories/GHSA-p3m8-78j2-g5p3
  - https://www.vulncheck.com/advisories/nltk-before-insecure-default-configuration-pathsec
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78680
rules:
  - title: Detect CVE-2026-78680 - Unexpected Execution of dot Binary
    description: Detects execution of the dot binary from suspicious or user-writable directories, potentially indicating an attempt to hijack the NLTK Graphviz dependency.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Engineering
  immediate_actions:
    - action: Upgrade NLTK package to 3.10.3
      owner: Engineering
      due: 48h
      evidence: CVE-2026-71513 requires version 3.10.3 for remediation
  mitigation_plan:
    - priority: immediate
      action: Restrict source of model files to trusted locations only
      owner: Engineering
      addresses: CVE-2026-71513
      evidence: Source explicitly warns against loading untrusted transition-parser models
updates:
  - at: "2026-08-22T15:31:12Z"
    level: L2
    summary: added coverage for nltk
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62384
  - at: "2026-08-22T15:31:19Z"
    level: L2
    summary: added coverage for NLTK (3.10.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62388
  - at: "2026-08-25T04:07:14Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-78680 - Unexpected Execution of dot Binary'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-78680
---

NLTK (Natural Language Toolkit) versions before 3.10.3 contain a remote code execution vulnerability in the AllowlistUnpickler component. The vulnerability, tracked as CVE-2026-71513, stems from insufficient validation logic; while the component validates the pickle module string, it fails to validate the global name. This oversight allows an attacker to resolve dotted names via attribute traversal, successfully bypassing the allowlist. 

By crafting and providing a malicious transition-parser model, an attacker can trigger arbitrary command execution when the `TransitionParser.parse` method invokes `allowlisted_pickle_load`. Because this involves the deserialization of untrusted data (CWE-502), any application utilizing NLTK to load untrusted transition-parser models is at risk. Defenders should prioritize updating NLTK to version 3.10.3 or later to remediate the flaw in the underlying pickle security logic.

## Attack Chain

1. Attacker generates a malicious transition-parser model file using crafted pickle payloads.
2. Attacker leverages attribute traversal to reference callables outside the intended allowlisted namespace.
3. Attacker delivers the malicious model to a target application that uses the NLTK library.
4. Target application invokes the `TransitionParser.parse` function, which subsequently calls `allowlisted_pickle_load`.
5. The `AllowlistUnpickler` fails to perform validation on the global name during deserialization.
6. The pickle loader executes the attacker-supplied malicious callable.
7. Arbitrary code executes within the context of the application process, leading to full system compromise or exfiltration.

## Impact

Successful exploitation allows for remote code execution, which can lead to complete compromise of the affected application environment. Given the widespread use of NLTK in data science and NLP pipelines, this vulnerability could impact numerous downstream services and automated systems that process user-provided model files. The CVSS 3.1 base score of 8.8 indicates a high severity rating with potential for full confidentiality, integrity, and availability impact.

## Recommendation

Prioritized actions for security and engineering teams:
- Upgrade NLTK to version 3.10.3 or later across all environments where natural language processing tasks are performed.
- Audit existing infrastructure to identify applications that load externally provided transition-parser models.
- Implement strict input validation and sandboxing for any component that processes serialized Python objects or untrusted model files.
- Monitor application logs for unexpected process spawns or network connections originating from Python environments using NLTK.
