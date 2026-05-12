---
title: Adobe Connect Incorrect Authorization Vulnerability (CVE-2026-34660)
slug: 2026-05-adobe-connect-auth-bypass
description: Adobe Connect versions 2025.9.15, 2025.8.157 and earlier are affected by an Incorrect Authorization vulnerability (CVE-2026-34660) that could lead to arbitrary code execution through malicious script injection, requiring user interaction.
date: "2026-05-12T19:17:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - authorization
  - code execution
  - adobe connect
vendors:
  - Adobe
products:
  - Connect
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-34660
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34660
  - CVE-2026-34660
rules:
  - title: Detect CVE-2026-34660 Exploitation Attempts — Script Injection in Adobe Connect
    description: Detects attempts to exploit CVE-2026-34660 by identifying suspicious script injection payloads in HTTP requests to Adobe Connect.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect CVE-2026-34660 Exploitation Attempts — Suspicious HTML Tags in Adobe Connect API Requests
    description: Detects attempts to exploit CVE-2026-34660 by identifying suspicious HTML tags injection in API requests to Adobe Connect.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

Adobe Connect versions 2025.9.15, 2025.8.157 and earlier are vulnerable to an Incorrect Authorization flaw identified as CVE-2026-34660. Successful exploitation could allow an attacker to execute arbitrary code within the context of the current user. The attack involves injecting malicious scripts into a web page, thereby potentially escalating privileges or gaining control over a victim's account or session. A crucial requirement for exploitation is user interaction, where the victim is enticed to visit a specially crafted URL or interact with a compromised web page. This vulnerability poses a significant risk to organizations relying on Adobe Connect for online collaboration and presentations.

## Attack Chain

1. The attacker crafts a malicious URL containing a script injection payload designed to exploit the incorrect authorization vulnerability.
2. The attacker distributes the malicious URL to potential victims, often through phishing or social engineering techniques.
3. A victim, upon clicking the malicious link, is redirected to a compromised Adobe Connect web page.
4. The injected script is executed within the victim's browser session due to the lack of proper authorization checks.
5. The attacker gains the ability to execute arbitrary code within the user's session, such as stealing cookies or session tokens.
6. The attacker uses stolen credentials or session tokens to impersonate the victim and gain unauthorized access to sensitive information or functionalities.
7. With elevated privileges, the attacker can manipulate data, modify configurations, or deploy further malicious payloads to other users.
8. The attacker achieves complete control over the targeted Adobe Connect environment, potentially exfiltrating sensitive data or disrupting services.

## Impact

Successful exploitation of CVE-2026-34660 can lead to a full system compromise, including sensitive data theft and unauthorized access to Adobe Connect resources. The vulnerability requires user interaction, which makes users who frequently access external links prime targets. The vulnerability allows an attacker to escalate privileges and potentially compromise entire Adobe Connect environments. Without remediation, affected organizations are at risk of significant data breaches and reputational damage.

## Recommendation

*   Upgrade to Adobe Connect version 2025.9.16 or later to patch CVE-2026-34660.
*   Implement a web application firewall (WAF) rule to detect and block requests containing suspicious script injection payloads targeting Adobe Connect endpoints (see example Sigma rule below).
*   Train users to identify and avoid clicking on suspicious links or interacting with untrusted web pages to mitigate the user interaction requirement.
*   Enable logging for web server activity and monitor for unusual patterns or attempts to access restricted resources to detect potential exploitation attempts.
