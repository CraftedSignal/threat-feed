---
title: OpenClaw Environment Filtering Bypass Vulnerability (CVE-2026-62199)
slug: 2026-07-openclaw-env-filter-bypass
description: A critical vulnerability, CVE-2026-62199, in OpenClaw versions prior to 2026.6.6 allows a lower-trust caller to bypass host execution environment filtering by supplying crafted interpreter startup variables, leading to unauthorized code execution and persistence.
date: "2026-07-13T22:29:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - persistence
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw (before 2026.6.6)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: supply crafted environment variables to execute or persist actions
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: supply crafted environment variables to execute or persist actions
    confidence_band: high
cves:
  - id: CVE-2026-62199
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62199
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-hjr6-g723-hmfm
  - https://www.vulncheck.com/advisories/openclaw-authentication-bypass-via-environment-filtering
---

CVE-2026-62199 identifies a significant flaw in OpenClaw versions before 2026.6.6. This vulnerability resides within the host execution environment filtering mechanism, which fails to adequately sanitize or block interpreter startup variables. When an affected OpenClaw instance has the vulnerable feature enabled and is reachable by a lower-trust caller or through a configured input path, an attacker can supply specially crafted environment variables. These malicious variables can exploit the filtering bypass to execute commands or establish persistence with elevated privileges beyond the caller's intended authorization. The CVSS 3.1 base score for this vulnerability is 8.8 (High), indicating a severe risk of compromise, including full confidentiality, integrity, and availability impacts.

## Attack Chain

1. An attacker, acting as a lower-trust caller or leveraging a configured input path, identifies a vulnerable OpenClaw instance (versions before 2026.6.6) with the susceptible feature enabled and network reachable.
2. The attacker researches the specific interpreter used by OpenClaw and identifies interpreter startup variables that can be manipulated for arbitrary command execution or persistence.
3. The attacker crafts a set of malicious environment variables designed to bypass OpenClaw's faulty host execution environment filtering.
4. The attacker supplies these crafted environment variables to the vulnerable OpenClaw instance through the designated input path or API.
5. Due to the flaw in the filtering mechanism (CVE-2026-62199), the malicious interpreter startup variables are not properly sanitized or blocked by OpenClaw.
6. The OpenClaw instance proceeds to execute the interpreter, inadvertently processing the attacker-controlled startup variables.
7. The malicious environment variables cause the interpreter to execute arbitrary commands supplied by the attacker, resulting in unauthorized code execution.
8. The attacker successfully gains control over the OpenClaw host system, potentially leading to data exfiltration, further persistence mechanisms, or deployment of additional malware.

## Impact

Successful exploitation of CVE-2026-62199 grants attackers unauthorized code execution and persistence capabilities on the compromised system. This can lead to complete system takeover, allowing for arbitrary command execution, data exfiltration, modification of system configurations, or deployment of additional malicious payloads such as ransomware or backdoors. While no specific victim numbers or targeted sectors are available from the advisory, the high CVSS score implies that any organization using vulnerable OpenClaw versions could be at significant risk of severe data breaches and operational disruption.

## Recommendation

* Patch CVE-2026-62199 immediately by upgrading all OpenClaw instances to version 2026.6.6 or later.
* Review the configuration of OpenClaw instances to ensure the affected feature, which enables external control over host exec environment filtering, is disabled if not strictly necessary.
* Monitor system and application logs for unusual process creations or modifications to environment variables originating from OpenClaw processes or its associated interpreter.
