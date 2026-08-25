---
title: Remote Code Execution in NLTK via Unsafe Pickle Deserialization
slug: 2026-08-nltk-pickle-rce
description: The NLTK library versions up to 3.9.4 are vulnerable to arbitrary code execution when processing crafted model files due to unsafe pickle deserialization in the TransitionParser.parse() method.
date: "2026-08-25T04:05:30Z"
lastmod: "2026-08-25T04:07:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - xml-vulnerability
  - cve-2026-78681
products:
  - NLTK (3.9.4)
  - nltk
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.006
    technique_name: Python
    evidence: When an application loads an attacker-crafted model file, embedded pickle gadget chains execute arbitrary Python code with the privileges of the user running the application.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can craft XML payloads with nested entity declarations that expand from hundreds of bytes to megabytes in memory, causing denial of service.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: NLTK before 3.10.3 contains a server-side request forgery vulnerability in nltk.pathsec.urlopen... allowing disclosure of internal HTTP resources, loading of forged downloader indexes, and installation of attacker-chosen package content.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker can supply a validated public URL that the proxy forwards to an internal loopback-only service, allowing... installation of attacker-chosen package content.
    confidence_band: high
cves:
  - id: CVE-2026-78683
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78683
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78681
  - https://github.com/nltk/nltk/security/advisories/GHSA-97qj-x29f-37w7
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78682
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade NLTK to 3.10.0 to remediate CVE-2026-78683
      owner: IT Operations
      due: 72h
      evidence: NLTK provides a RestrictedUnpickler for safe deserialization, but it is not used by production code paths. Fixed in 3.10.0.
  mitigation_plan:
    - priority: immediate
      action: Identify and isolate services using TransitionParser in NLTK until patch can be applied
      owner: IT Operations
      addresses: CVE-2026-78683
      evidence: The TransitionParser.parse() method calls pickle_load() with the default restricted=False
updates:
  - at: "2026-08-25T04:07:21Z"
    level: L1
    summary: added coverage for nltk
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-78681
  - at: "2026-08-25T04:07:30Z"
    level: L2
    summary: added coverage for NLTK
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-78682
---

NLTK (Natural Language Toolkit) versions prior to 3.10.0 contain a critical vulnerability in the TransitionParser.parse() method, located within the nltk/parse/transitionparser.py file. This vulnerability arises because the library uses an insecure default setting for the pickle_load() function, specifically setting restricted=False. By default, this utilizes the standard WarningUnpickler which fails to restrict class resolution during the deserialization process.

When an application utilizing NLTK processes an attacker-controlled or malicious model file, the deserialization of that object allows for the execution of arbitrary Python code. This occurs because the library does not utilize the provided RestrictedUnpickler for production tasks, thereby allowing gadget chains to execute within the context of the running application. This vulnerability is patched in version 3.10.0 and carries a CVSS 3.1 base score of 9.6.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code with the full privileges of the user running the application. This could lead to full system compromise, data exfiltration, or the deployment of persistent threats depending on the service's environment. Applications that process untrusted NLTK model files are at the highest risk.

## Recommendation

1. Upgrade the NLTK library to version 3.10.0 or later across all production and development environments.
2. Implement strict input validation or signing for all model files processed by applications to ensure they originate from a trusted source.
3. Audit applications using the TransitionParser module to ensure that user-supplied input is not directly passed to the parsing engine.
4. Restrict application service account permissions to the principle of least privilege to minimize the impact of a potential RCE event.
