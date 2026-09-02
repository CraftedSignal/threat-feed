---
title: Unauthenticated OS Command Injection in Kestra OSS (CVE-2026-49869)
slug: 2026-09-kestra-rce
description: Kestra OSS contains an OS command injection vulnerability allowing unauthenticated remote attackers to create and execute arbitrary workflows, posing a risk of full system compromise.
date: "2026-09-02T17:56:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:kestra:kestra:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - command-injection
vendors:
  - Kestra
products:
  - Kestra OSS (< 1.0.45)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Kestra OSS contains an OS command injection vulnerability that could allow an unauthenticated remote attacker to create and execute arbitrary workflows without credentials.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Kestra OSS contains an OS command injection vulnerability that could allow an unauthenticated remote attacker to create and execute arbitrary workflows.
    confidence_band: high
cves:
  - id: CVE-2026-49869
    cvss: 10
    epss: 0.00991
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-49869
  - https://github.com/kestra-io/kestra/security/advisories/GHSA-5vc5-wxxq-3fjx
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
  - https://nvd.nist.gov/vuln/detail/CVE-2026-49869
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Kestra OSS to 1.0.45 or later
      owner: IT Operations
      due: "2026-09-05"
      evidence: CISA BOD 26-04 requirement.
  mitigation_plan:
    - priority: immediate
      action: Patch Kestra OSS to 1.0.45 or later
      owner: IT Operations
      addresses: CVE-2026-49869
      evidence: Vendor advisory and CISA-KEV.
---

Kestra OSS is affected by an OS command injection vulnerability (CVE-2026-49869) that enables unauthenticated remote attackers to interact with the platform's workflow execution engine. By exploiting this flaw, an attacker can bypass authentication mechanisms to create, inject, and execute arbitrary workflows. This represents a significant security risk, as the platform is designed to orchestrate system processes and automation tasks, granting a successful attacker the ability to perform operations with the privileges of the Kestra service. Defenders should prioritize auditing internet-facing Kestra instances, as this vulnerability provides a direct vector for remote code execution and potential lateral movement within a target environment.

## Impact

Successful exploitation of CVE-2026-49869 allows an unauthenticated actor to execute arbitrary commands, potentially leading to unauthorized data exfiltration, system-wide disruption, or the establishment of persistent backdoors within the affected organization's infrastructure.

## Recommendation

- Immediately identify all internet-facing instances of Kestra OSS and verify their version against vendor-provided security patches.
- Review all system-level logs for unauthorized workflow creation or execution requests originating from untrusted IP addresses.
- Implement network-level restrictions to prevent public access to Kestra management interfaces unless strictly necessary for business operations.
- Adhere to CISA BOD 26-04 requirements by ensuring the vulnerability is patched within the mandated timeframe (by 2026-09-05) and performing the required forensics triage as outlined in CISA's implementation guidance.
