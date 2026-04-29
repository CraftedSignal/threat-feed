---
title: Angular Cross-Site Scripting (XSS) Vulnerability
slug: 2026-03-angular-xss
description: A cross-site scripting (XSS) vulnerability exists in Angular versions prior to 22.0.0-next.3, 21.2.4, 20.3.18, and 19.2.20, allowing attackers to execute arbitrary code within the context of the vulnerable application, potentially leading to session hijacking, data exfiltration, and unauthorized actions.
date: "2026-03-17T19:19:33Z"
type: coverage
types:
  - coverage
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

A cross-site scripting (XSS) vulnerability has been identified in the Angular framework, specifically affecting versions prior to 22.0.0-next.3, 21.2.4, 20.3.18, and 19.2.20. The vulnerability stems from the interaction between security-sensitive attributes (e.g., href) and Angular's internationalization features. When internationalization is enabled for such attributes using `i18n-name`, the built-in sanitization mechanisms can be bypassed. This can be exploited by injecting malicious scripts through data bindings that handle untrusted, user-generated data. Successful exploitation allows an attacker to execute arbitrary code within the context of the affected application's domain. Immediate patching is strongly advised.

## Attack Chain

1.  The attacker identifies an Angular application using a vulnerable version (prior to 22.0.0-next.3, 21.2.4, 20.3.18, or 19.2.20).
2.  The attacker locates an input field or URL parameter that allows the injection of user-controlled data into an `href` attribute (or another security-sensitive attribute).
3.  The attacker crafts a malicious payload containing JavaScript code. The payload leverages the `i18n-name` attribute in conjunction with data binding to bypass sanitization.
4.  The attacker injects the malicious payload into the targeted input field or URL parameter.
5.  The victim user interacts with the application, triggering the rendering of the malicious payload within the vulnerable attribute.
6.  The injected JavaScript code executes within the victim's browser, operating under the security context of the Angular application's domain.
7.  The attacker gains the ability to perform actions such as stealing session cookies or authentication tokens (session hijacking).
8.  The attacker can then exfiltrate sensitive data or perform unauthorized actions on behalf of the user.

## Impact

Successful exploitation of this XSS vulnerability allows attackers to execute arbitrary code within the context of the vulnerable Angular application. This can lead to session hijacking, enabling attackers to impersonate users and access their data. Data exfiltration is also possible, allowing attackers to steal sensitive information such as personal data or financial details. Furthermore, attackers can perform unauthorized actions on behalf of the user, potentially leading to financial loss, reputational damage, or other adverse consequences. The CCB strongly recommends immediate patching.

## Recommendation

*   Upgrade Angular installations to versions 22.0.0-next.3, 21.2.4, 20.3.18, or 19.2.20 to remediate the vulnerability as per the vendor advisory ([https://github.com/angular/angular/security/advisories/GHSA-g93w-mfhg-p222](https://github.com/angular/angular/security/advisories/GHSA-g93w-mfhg-p222)).
*   Implement a Web Application Firewall (WAF) with rules to detect and block common XSS payloads. This can provide an additional layer of defense against exploitation attempts.
*   Enable and review web server access logs for suspicious activity and potential XSS attempts. Analyze logs for unusual URL parameters or POST data containing script-like syntax.
