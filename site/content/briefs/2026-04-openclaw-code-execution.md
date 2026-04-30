---
title: OpenClaw Approval Integrity Vulnerability Leads to Code Execution (CVE-2026-32971)
slug: 2026-04-openclaw-code-execution
description: OpenClaw before 2026.3.11 exhibits an approval-integrity vulnerability where attackers can place wrapper binaries to execute local code after operators approve misleading command text, due to the system displaying extracted shell payloads instead of the actual executed arguments.
date: "2026-03-31T12:17:43Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-32971
  - code-execution
  - approval-bypass
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
cves:
  - id: CVE-2026-32971
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32971
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-rw39-5899-8mxp
  - https://www.vulncheck.com/advisories/openclaw-node-host-approval-ui-mismatch-allows-execution-of-unintended-commands
rules:
  - title: Detect Suspicious OpenClaw Command Execution
    description: Detects suspicious command execution within OpenClaw by monitoring for command lines that contain potentially malicious code.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious OpenClaw Wrapper Binary Use
    description: Detects the execution of potentially malicious wrapper binaries within OpenClaw's environment.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw, a software platform (details unspecified in the source), is vulnerable to an approval-integrity issue (CVE-2026-32971) affecting versions prior to 2026.3.11. This vulnerability resides within the `node-host system.run` approval process. The system displays extracted shell payloads instead of the actual arguments (`argv`) that will be executed. An attacker can exploit this by crafting malicious commands using wrapper binaries. By inducing operators to approve what appears to be benign…
