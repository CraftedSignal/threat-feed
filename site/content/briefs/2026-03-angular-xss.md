---
title: Angular Cross-Site Scripting (XSS) Vulnerability
slug: 2026-03-angular-xss
description: A cross-site scripting (XSS) vulnerability exists in Angular versions prior to 22.0.0-next.3, 21.2.4, 20.3.18, and 19.2.20, allowing attackers to execute arbitrary code within the context of the vulnerable application, potentially leading to session hijacking, data exfiltration, and unauthorized actions.
date: "2026-03-17T19:19:33Z"
severities:
  - high
tags:
  - angular
  - xss
  - vulnerability
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1185
    technique_name: Compromise Accounts
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://ccb.belgium.be/advisories/warning-xss-vulnerability-angular-patch-immediately
  - https://github.com/angular/angular/security/advisories/GHSA-g93w-mfhg-p222
rules:
  - title: Detect Suspicious URI with common XSS patterns
    description: Detects potential XSS attempts in URI parameters using common XSS patterns
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - web
      - apache|nginx|iis
  - title: Detect Suspicious POST Request with common XSS patterns
    description: Detects potential XSS attempts in POST data using common XSS patterns
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - web
      - apache|nginx|iis
rules_count: 2
---

A cross-site scripting (XSS) vulnerability has been identified in the Angular framework, specifically affecting versions prior to 22.0.0-next.3, 21.2.4, 20.3.18, and 19.2.20. The vulnerability stems from the interaction between security-sensitive attributes (e.g., href) and Angular's internationalization features. When internationalization is enabled for such attributes using `i18n-name`, the built-in sanitization mechanisms can be bypassed. This can be exploited by injecting malicious scripts…
