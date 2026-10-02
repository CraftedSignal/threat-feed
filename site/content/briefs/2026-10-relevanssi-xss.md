---
title: Stored XSS in Relevanssi - A Better Search WordPress Plugin
slug: 2026-10-relevanssi-xss
description: The Relevanssi plugin for WordPress is vulnerable to stored Cross-Site Scripting (XSS) due to insufficient input sanitization of comment content, allowing unauthenticated attackers to execute arbitrary scripts.
date: "2026-10-02T08:24:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:relevanssi:a_better_search:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - wordpress
  - xss
vendors:
  - Relevanssi
products:
  - Relevanssi – A Better Search (<= 4.28.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Relevanssi – A Better Search plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Comment Content in all versions up to, and including, 4.28.3.
    confidence_band: high
cves:
  - id: CVE-2026-97641
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97641
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Relevanssi - A Better Search plugin to a version later than 4.28.3.
      owner: IT Operations
      addresses: CVE-2026-97641
      evidence: Plugin version 4.28.3 and below identified as vulnerable.
---

The Relevanssi - A Better Search plugin for WordPress is vulnerable to a stored Cross-Site Scripting (XSS) vulnerability in all versions up to and including 4.28.3. The issue stems from insufficient input sanitization and output escaping of comment content processed by the plugin. Attackers can leverage this flaw to inject arbitrary malicious web scripts into the site's content.

The exploit condition is specific: it requires the site administrator to have configured the "Allowable tags in excerpts" setting to a non-empty value (such as the default `<p><a><strong>`). Because the plugin utilizes a prefix-matching regex for tag validation, an attacker can inject a malicious tag name if that name begins with one of the configured allowed tags. When a user, typically an administrator, accesses an page containing the injected content, the malicious script executes in their browser context, potentially leading to unauthorized actions or session compromise.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of other users or administrators viewing the site. This may result in unauthorized administrative actions, session hijacking, or defacement. The vulnerability affects all users running Relevanssi versions 4.28.3 and older.

## Recommendation

Prioritized actions for security teams:
- Update the Relevanssi - A Better Search plugin to the latest available version (beyond 4.28.3) where input sanitization has been corrected.
- Review the "Allowable tags in excerpts" setting in the WordPress administrative console and remove unnecessary or permissive tags that could facilitate prefix-matching bypasses.
- Audit WordPress comment logs for suspicious HTML or script injection patterns if the plugin has been active with broad tag allowances.
