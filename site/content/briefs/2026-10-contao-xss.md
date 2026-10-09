---
title: Stored Cross-Site Scripting in Contao Comments Bundle
slug: 2026-10-contao-xss
description: An unauthenticated stored XSS vulnerability in the Contao comments-bundle allows remote attackers to execute arbitrary JavaScript in the context of administrative sessions, potentially leading to full system compromise.
date: "2026-10-09T21:23:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:contao:comments_bundle:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - cve
vendors:
  - Contao
products:
  - comments-bundle (4.0.0 <= v < 5.3.50)
  - comments-bundle (5.4.0-RC1 <= v < 5.7.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated front end visitor can post a comment containing a XSS injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The victim is any back end user who opens the Comments module, and moderation makes exposure certain rather than preventing it.
    confidence_band: high
cves:
  - id: CVE-2026-107845
    cvss: 9.3
references:
  - https://github.com/advisories/GHSA-628f-v4f6-p37r
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107845
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade composer/contao/comments-bundle to 5.3.50 or 5.7.12
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-107845 remediation requirements
  mitigation_plan:
    - priority: immediate
      action: Deploy strict Content-Security-Policy (CSP) headers to restrict script sources on back-end modules
      owner: IT Operations
      addresses: CVE-2026-107845
      evidence: Source notes lack of CSP header in Contao back-end
---

The Contao comments-bundle is vulnerable to stored cross-site scripting (XSS) due to improper input sanitization in the front-end comment submission mechanism. Tracked as CVE-2026-107845, this vulnerability allows unauthenticated attackers to submit comments containing malicious payloads that persist within the application database. When an administrator or moderator accesses the back-end Comments module to review pending submissions, the injected script executes automatically within their browser session.

Because the Contao back-end lacks a robust Content-Security-Policy (CSP), the payload can perform any action available to the authenticated administrator, including modifying system templates, creating new administrative accounts, or exfiltrating session tokens. The design of the module ensures that moderation activity triggers the vulnerability, making it highly effective for attackers seeking to target administrative users.

## Impact

The vulnerability poses a critical risk to Contao installations, enabling unauthenticated remote attackers to gain administrative control over the application. Successful exploitation leads to full application compromise, as the attacker can leverage the administrative interface to inject malicious code into templates, resulting in server-side remote code execution. The scope of impact includes any Contao instance using the vulnerable versions of the comments-bundle, with no user interaction required beyond an administrator accessing the moderation interface.

## Recommendation

- Update the Contao comments-bundle to version 5.3.50 or later, or 5.7.12 or later, to incorporate necessary input sanitization.
- Implement a strict Content-Security-Policy (CSP) on the back-end to mitigate the impact of potential XSS vulnerabilities until all components are updated.
- Audit administrative logs for unexpected account creation or template modifications occurring in proximity to comment moderation activity.
