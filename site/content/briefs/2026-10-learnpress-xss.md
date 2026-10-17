---
title: Stored Cross-Site Scripting in LearnPress WordPress Plugin
slug: 2026-10-learnpress-xss
description: The LearnPress WordPress plugin is vulnerable to Stored Cross-Site Scripting via the 'quantity' and 'order_comments' parameters, allowing script injection by unauthenticated or low-privileged users.
date: "2026-10-17T04:48:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:thimpress:learnpress:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - web-application-vulnerability
vendors:
  - ThimPress
products:
  - LearnPress (<= 4.4.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-109208
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109208
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade LearnPress to a version beyond 4.4.10.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-109208 indicates versions <= 4.4.10 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Disable guest checkout in LearnPress settings.
      owner: IT Operations
      addresses: CVE-2026-109208
      evidence: The source confirms guest checkout allows unauthenticated exploitation.
---

The LearnPress - WordPress LMS Plugin for Create and Sell Online Courses, developed by ThimPress, contains a Stored Cross-Site Scripting (XSS) vulnerability in all versions up to and including 4.4.10. The vulnerability exists due to insufficient sanitization and escaping of user-provided input within the 'quantity' (REST API) and 'order_comments' (checkout) parameters. 

If the site administrator has enabled the guest checkout feature, an unauthenticated attacker can exploit this flaw to inject arbitrary malicious web scripts. Even if guest checkout is disabled, any registered user with Subscriber-level privileges can trigger the injection during the checkout process. Once the script is stored, it executes in the browser of any user (such as an administrator or other customers) who accesses the affected checkout or order comment pages. This can lead to account takeover, sensitive data theft, or unauthorized actions performed on behalf of the victim.

## Impact

Successful exploitation allows for the execution of malicious scripts in the context of other users on the WordPress site. In multi-user environments such as LMS platforms, this poses a high risk to administrative sessions and sensitive user data. The impact is significant for organizations relying on LearnPress to manage course transactions and user profiles, as attackers could potentially compromise high-privileged accounts or intercept payment-related comments.

## Recommendation

1. Update the LearnPress plugin immediately to a version newer than 4.4.10.
2. Until a patch is applied, disable the guest checkout functionality to restrict the exploit surface to authenticated users.
3. Monitor web server logs for suspicious POST requests to the checkout and REST API endpoints that include scripts or HTML tags.
4. Implement a robust Content Security Policy (CSP) to mitigate the impact of XSS attacks by restricting where scripts can be loaded from and executed.
