---
title: Critical Vulnerabilities in Adobe Campaign Classic
slug: 2026-08-adobe-campaign-classic
description: Adobe Campaign Classic is affected by three critical vulnerabilities, including SSRF and OS Command Injection, which allow unauthenticated remote attackers to achieve full system compromise.
date: "2026-08-27T12:40:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:adobe:dimension:*:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:indesign:*:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:after_effects:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - adobe
  - ssrf
vendors:
  - Adobe
products:
  - Campaign Classic
cves:
  - id: CVE-2024-41865
    cvss: 7.8
    epss: 0.00335
  - id: CVE-2024-41866
    cvss: 5.5
    epss: 0.00262
  - id: CVE-2024-41867
    cvss: 5.5
    epss: 0.00268
references:
  - https://www.ncsc.nl/alerts/kritieke-kwetsbaarheden-in-adobe-campaign-classic-met-risico-op-systeemcompromitatie
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Adobe Campaign Classic installations to address CVE-2024-41865, CVE-2024-41866, and CVE-2024-41867
      owner: IT Operations
      due: 24h
      evidence: NCSC-NL alert advises installation of security updates as soon as possible
---

The NCSC-NL has identified three critical vulnerabilities in Adobe Campaign Classic, carrying a maximum CVSS score of 10.0. These flaws include Server-Side Request Forgery (SSRF) and OS Command Injection, both of which can be triggered without user interaction by an unauthenticated attacker. The exploitation of these vulnerabilities allows for remote code execution and unauthorized access to the underlying server infrastructure. Given the high potential for system compromise, organizations running Adobe Campaign Classic are advised to apply the latest security patches provided by Adobe as a matter of urgency. The vulnerabilities are identified as CVE-2024-41865, CVE-2024-41866, and CVE-2024-41867.

## Impact

Successful exploitation of these vulnerabilities results in unauthorized remote access to the host server running Adobe Campaign Classic. This allows attackers to execute arbitrary commands, exfiltrate sensitive data, or pivot into the internal network. The NCSC-NL assesses the potential damage to organizations as 'high'.

## Recommendation

- Immediately apply the security updates provided by Adobe to remediate CVE-2024-41865, CVE-2024-41866, and CVE-2024-41867.
- Review web server logs for suspicious requests involving anomalous URI parameters or outbound connections originating from the Adobe Campaign Classic application server that may indicate exploitation attempts.
