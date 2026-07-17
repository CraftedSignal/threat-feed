---
title: OpenClaw Environment Variable Filtering Vulnerability Allows Execution and Persistence
slug: 2026-07-openclaw-env-var-vuln
description: OpenClaw versions prior to 2026.6.6 contain an environment variable filtering vulnerability in its host exec component that fails to properly sanitize rustup startup variables, allowing attackers with lower-trust caller access or configured input paths to execute or persist actions beyond their intended authorization level.
date: "2026-07-17T02:23:26Z"
lastmod: "2026-07-17T02:23:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-62203
  - vulnerability
  - environment-variable
  - code-execution
  - persistence
vendors:
  - OpenClaw
products:
  - OpenClaw (before 2026.6.6)
  - OpenClaw (< 2026.6.6)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: OpenClaw versions before 2026.6.6 contain an environment variable filtering vulnerability in host exec that fails to properly sanitize rustup startup variables. Attackers... can execute... actions beyond their intended authorization level.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Attackers with lower-trust caller access or configured input paths can ... persist actions beyond their intended authorization level.
    confidence_band: high
cves:
  - id: CVE-2026-62203
    cvss: 8.8
  - id: CVE-2026-62205
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62203
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-wxh3-g47h-q3mc
  - https://www.vulncheck.com/advisories/openclaw-environment-variable-injection-via-rustup
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62205
updates:
  - at: "2026-07-17T02:23:53Z"
    level: L2
    summary: added CVE-2026-62205
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62205
---

A high-severity vulnerability, identified as CVE-2026-62203, affects OpenClaw versions before 2026.6.6. This flaw resides within the `host exec` component, which is responsible for executing commands, and specifically relates to its failure to properly sanitize `rustup` startup environment variables. Attackers who have already gained lower-trust caller access to a system running a vulnerable OpenClaw application, or who can provide input through configured paths, can exploit this vulnerability. Successful exploitation grants the attacker the ability to execute arbitrary commands or establish persistence on the affected system, bypassing intended authorization levels and potentially leading to full system compromise. The vulnerability was published on July 17, 2026.

## Attack Chain

1. An attacker obtains "lower-trust caller access" to a system or can provide input via "configured input paths" to an OpenClaw application.
2. The attacker manipulates inputs or environment variables passed to the OpenClaw application.
3. The OpenClaw application invokes its `host exec` component to perform an action.
4. During this execution, the `host exec` component fails to properly sanitize `rustup` startup environment variables crafted by the attacker.
5. The unsanitized environment variables allow the injection of malicious commands or modification of the legitimate execution flow.
6. The system executes attacker-controlled commands under the context of the vulnerable application.
7. The attacker achieves unauthorized command execution and/or establishes persistence mechanisms on the compromised system.

## Impact

Successful exploitation of CVE-2026-62203 can lead to severe consequences, including complete compromise of the confidentiality, integrity, and availability of the affected system. Attackers can execute arbitrary code, potentially leading to data exfiltration, system corruption, or the deployment of additional malicious payloads such as ransomware. The ability to establish persistence means that attackers can maintain access to the compromised system even after reboots or security remediations, enabling long-term unauthorized control. This vulnerability poses a significant risk to organizations using affected OpenClaw versions, as it can allow threat actors to escalate privileges and achieve their objectives.

## Recommendation

* Patch CVE-2026-62203 immediately by updating OpenClaw to version 2026.6.6 or later to remediate the environment variable filtering vulnerability.
* Review access controls to OpenClaw applications to ensure that only trusted callers can interact with them and that all input paths are rigorously validated.
