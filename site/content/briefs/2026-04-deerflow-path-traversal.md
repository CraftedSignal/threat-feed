---
title: ByteDance DeerFlow Path Traversal and Arbitrary File Write Vulnerability
slug: 2026-04-deerflow-path-traversal
description: ByteDance DeerFlow before commit 2176b2b contains a path traversal and arbitrary file write vulnerability in bootstrap-mode custom-agent creation where the agent name validation is bypassed, allowing attackers to write files outside the intended custom-agent directory.
date: "2026-04-17T17:17:09Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path-traversal
  - file-write
  - bytedance
  - deerflow
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Controls
cves:
  - id: CVE-2026-40518
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40518
  - https://github.com/bytedance/deer-flow/commit/2176b2bbfccfce25ceee08318813f96d843a13fd
  - https://github.com/bytedance/deer-flow/pull/2274
  - https://www.vulncheck.com/advisories/bytedance-deerflow-path-traversal-and-arbitrary-file-write-via-bootstrap-mode
rules:
  - title: Detect Suspicious DeerFlow Agent Creation
    description: Detects the creation of custom agents with suspicious names indicative of path traversal attempts in ByteDance DeerFlow
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1553.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Arbitrary File Writes via DeerFlow
    description: Detects file writes outside the standard custom agent directory.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1553.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

ByteDance DeerFlow, a software of unknown purpose, prior to commit 2176b2b, is vulnerable to path traversal and arbitrary file write. The vulnerability lies within the bootstrap-mode custom-agent creation process, specifically due to insufficient validation of the agent name. This flaw allows attackers to bypass intended directory restrictions and write files to arbitrary locations on the system, provided they have the necessary filesystem permissions. The vulnerability was reported on April 17, 2026 and has been assigned CVE-2026-40518. Exploitation of this vulnerability could lead to privilege escalation and system compromise. Defenders should prioritize patching or mitigating this vulnerability to prevent unauthorized file modifications.

## Attack Chain

1.  Attacker gains low-privileged access to the DeerFlow application.
2.  Attacker initiates the creation of a custom agent in bootstrap mode.
3.  The attacker crafts a malicious agent name containing path traversal sequences (e.g., "../", absolute paths).
4.  The DeerFlow application fails to properly validate the agent name.
5.  The application uses the attacker-supplied agent name to create directories.
6.  The path traversal in the agent name allows the application to create directories outside the intended custom-agent directory.
7.  The attacker uploads files as part of the custom agent creation.
8.  The application writes these files to the attacker-controlled location, resulting in arbitrary file write.

## Impact

Successful exploitation of this vulnerability allows attackers to write arbitrary files to the file system, potentially overwriting system files or planting malicious executables. This could lead to privilege escalation, arbitrary code execution, and complete system compromise. While the number of affected installations is unknown, any system running a vulnerable version of ByteDance DeerFlow is susceptible to this attack. The severity is compounded by the ease of exploitation, requiring only low-privileged access.

## Recommendation

*   Apply the patch or upgrade to a version of ByteDance DeerFlow that includes commit 2176b2b to remediate the vulnerability referenced by CVE-2026-40518.
*   Implement the Sigma rule `Detect Suspicious DeerFlow Agent Creation` to detect exploitation attempts targeting CVE-2026-40518 by monitoring process creation events.
*   Monitor web server logs for unusual activity related to custom agent creation endpoints in DeerFlow to detect potential exploitation attempts.
