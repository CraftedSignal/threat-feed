---
title: OS Command Injection Vulnerability in SambaBox
slug: 2026-10-sambabox-rce
description: SambaBox versions prior to 5.4.1 are vulnerable to OS command injection, allowing unauthenticated attackers to execute arbitrary commands with application privileges.
date: "2026-10-06T14:56:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:felisify_information_technologies_industry_and_trade:sambabox:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - command-injection
vendors:
  - Felisify Information Technologies Industry and Trade Inc.
products:
  - SambaBox (< 5.4.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: SambaBox allows OS Command Injection.
    confidence_band: high
cves:
  - id: CVE-2026-85523
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85523
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade SambaBox to 5.4.1 or later
      owner: IT Operations
      due: 24h
      evidence: SambaBox versions prior to 5.4.1 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade SambaBox to 5.4.1
      owner: IT Operations
      addresses: CVE-2026-85523
      evidence: NVD vulnerability disclosure
---

Felisify Information Technologies Industry and Trade Inc. has disclosed a critical security vulnerability, CVE-2026-85523, affecting the SambaBox platform. The vulnerability arises from improper neutralization of special elements used in OS commands, enabling an OS command injection flaw. This issue specifically impacts all SambaBox versions prior to 5.4.1. By sending crafted malicious inputs to the application, an unauthenticated attacker can bypass existing input sanitization filters to execute arbitrary commands on the underlying host operating system. Given the application's typical deployment, successful exploitation results in full system compromise, allowing the attacker to establish persistence, move laterally within the network, or exfiltrate sensitive data. Defenders should prioritize patching to version 5.4.1 or later to remediate this vulnerability.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary OS commands with the privileges of the SambaBox application. This could lead to a complete system takeover, unauthorized access to network resources, and potential exfiltration of data managed by the SambaBox instance. Organizations utilizing SambaBox in public-facing or sensitive internal segments are at significant risk.

## Recommendation

Prioritized actions for security and IT operations teams:

- Upgrade all instances of SambaBox to version 5.4.1 or later immediately to address CVE-2026-85523.
- Audit logs for the SambaBox web interface for unusual input patterns containing shell metacharacters such as semicolon, pipe, ampersand, or backticks.
- Restrict network access to the SambaBox management interface to trusted administrative segments to reduce the attack surface until patching can be completed.
