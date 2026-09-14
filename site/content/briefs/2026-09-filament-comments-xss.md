---
title: Stored XSS in parallax filament-comments
slug: 2026-09-filament-comments-xss
description: CVE-2026-90943 is a stored cross-site scripting vulnerability in filament-comments <= 3.0.0, allowing authenticated users to inject malicious scripts into comment bodies for execution in the browsers of other users.
date: "2026-09-14T17:34:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:parallax:filament-comments:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - php
vendors:
  - parallax
products:
  - filament-comments (<= 3.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability exists within the comment body rendering functionality, allowing an authenticated panel user to inject malicious JavaScript.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90943
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade filament-comments to the patched version
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-90943
  mitigation_plan:
    - priority: immediate
      action: Apply Content Security Policy (CSP) to restrict script execution
      owner: Security Engineering
      addresses: CVE-2026-90943
---

CVE-2026-90943 identifies a stored cross-site scripting (XSS) vulnerability within the parallax filament-comments package for the Filament PHP framework, affecting all versions up to and including 3.0.0. The vulnerability resides in the comment body rendering component, which fails to properly sanitize user-supplied input before displaying it in the administrative panel or public-facing views. An authenticated user can inject malicious JavaScript into a comment body. When a victim, such as an administrator with higher privileges, views the rendered comment, the malicious payload executes in their browser session. This flaw poses a significant risk to the integrity of the administrative session, potentially allowing for session token theft, unauthorized data access, or the performance of administrative actions on behalf of the victim. Defenders should prioritize updating to a patched version or implementing strict content security policies to mitigate script execution.

## Impact

Successful exploitation allows for the execution of arbitrary JavaScript within the security context of a logged-in user. In an administrative panel, this facilitates account takeover via session hijacking or the unauthorized modification of system settings, impacting the confidentiality and integrity of the affected application.

## Recommendation

- Upgrade the parallax filament-comments package to the latest version that includes sanitization patches for comment body rendering.
- Implement a Content Security Policy (CSP) that restricts script sources and prevents the execution of inline scripts to mitigate the impact of potential XSS vulnerabilities.
- Review administrative access logs for unusual activity associated with user accounts that have recently posted comments.
