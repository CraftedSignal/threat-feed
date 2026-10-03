---
title: Stored Cross-Site Scripting in SEOPress WordPress Plugin
slug: 2026-10-seopress-xss
description: A stored XSS vulnerability in SEOPress versions up to 10.2 allows unauthenticated attackers to execute arbitrary scripts by injecting malicious code into the Author Display Name field.
date: "2026-10-03T06:54:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:seopress:seopress:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - web-vulnerability
vendors:
  - SEOPress
products:
  - SEOPress – AI SEO Plugin & On-site SEO plugin for WordPress (<= 10.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-96564
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96564
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade SEOPress to version 10.3 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-96564 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Disable 'Track Authors' custom dimension in GA4 or Matomo settings
      owner: IT Operations
      addresses: CVE-2026-96564
      evidence: Source description of vulnerability configuration requirements
---

SEOPress, a popular SEO plugin for WordPress, contains a stored Cross-Site Scripting (XSS) vulnerability identified as CVE-2026-96564. The flaw affects all versions up to and including 10.2. It stems from improper input sanitization and output escaping within the plugin's handling of the Author Display Name. This vulnerability is specific to configurations where the 'Track Authors' custom dimension is active within Google Analytics 4 or Matomo integration settings. When these conditions are met, the plugin includes the unsanitized display name within tracking scripts rendered on public-facing pages. Attackers can leverage this by submitting malicious content through components that allow public singular content creation, such as bbPress, where the injected payload in the display name is later reflected and executed in the browsers of visiting users.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a victim's browser session. This can be used for session hijacking, credential theft, or the silent redirection of users to malicious websites. The impact is significant for sites with high traffic or those relying on third-party forums or user-generated content plugins integrated with SEOPress.

## Recommendation

1. Upgrade SEOPress to version 10.3 or later immediately to patch CVE-2026-96564.
2. Audit current plugin settings and temporarily disable the 'Track Authors' feature in Google Analytics 4 or Matomo until the software can be updated.
3. Review logs for suspicious activity originating from public-facing content submission points such as bbPress.
