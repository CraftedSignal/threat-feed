---
title: Stored XSS in Kirki WordPress Plugin via Registration Metadata
slug: 2026-10-kirki-xss
description: The Kirki plugin for WordPress is vulnerable to Stored XSS due to insufficient input validation in registration metadata, allowing unauthenticated attackers to inject malicious scripts.
date: "2026-10-07T06:34:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kirki:freeform_page_builder_website_builder_customizer:*:*:*:*:*:*:*:*
vendors:
  - Kirki
products:
  - Kirki – Freeform Page Builder, Website Builder & Customizer (<= 6.3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: inject arbitrary web scripts that execute whenever a user accesses a page
    confidence_band: high
cves:
  - id: CVE-2026-102173
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102173
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Kirki to the latest version to patch CVE-2026-102173
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-102173 advisory
  mitigation_plan:
    - priority: immediate
      action: Disable public user registration if not strictly required
      owner: IT Operations
      addresses: CVE-2026-102173
      evidence: Requires public user registration to be enabled
---

The Kirki plugin for WordPress, specifically versions up to and including 6.3.1, contains a security vulnerability identified as CVE-2026-102173. The flaw resides in the `ExceptionalElements::image_element()` method, which improperly escapes user-meta values before concatenating them into HTML `<img>` tag attributes. An unauthenticated attacker can exploit this by submitting malicious payloads through registration metadata fields. When a page containing a `kirki-register` element renders the affected metadata, the injected script executes in the context of the user's browser. Successful exploitation requires the target WordPress site to have public user registration enabled and to feature a page with the `kirki-register` element, which is necessary to capture the required nonces for the injection.

## Impact

The vulnerability allows unauthenticated attackers to perform Stored Cross-Site Scripting (XSS). If successfully exploited, this can lead to session hijacking, unauthorized actions performed on behalf of authenticated users, or the redirection of visitors to malicious sites. The scope of impact is limited to WordPress installations utilizing the Kirki plugin where public registration is active and the specific page component is present.

## Recommendation

1. Upgrade the Kirki plugin to the latest patched version available.
2. Disable public user registration on WordPress sites if it is not a business requirement.
3. Monitor web server access logs for anomalous registration activity or suspicious characters in form submissions targeting user-meta fields.
4. Implement Content Security Policy (CSP) headers to mitigate the impact of potential XSS attacks by restricting the execution of inline scripts and unauthorized external sources.
