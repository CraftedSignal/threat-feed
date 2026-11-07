---
brief_id: brief-2026-11-07-iubenda-xss
event_id: brief-2026-11-07-iubenda-xss
revision: 1
activity_at: "2026-11-07T03:46:48Z"
title: 'iubenda All-in-one Compliance: Stored Cross-Site Scripting (CVE-2026-120540)'
slug: 2026-11-iubenda-xss
description: The iubenda All-in-one Compliance plugin for WordPress up to version 3.13.6 is vulnerable to stored Cross-Site Scripting (XSS) due to insecure re-processing of HTML comments by its bundled simple_html_dom parser.
date: "2026-11-07T03:46:48Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:iubenda:all-in-one_compliance_for_gdpr_/_ccpa_cookie_consent_+_more:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - web-application
  - cve-2026-120540
vendors:
  - iubenda
products:
  - All-in-one Compliance for GDPR / CCPA Cookie Consent + more (<= 3.13.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page
    confidence_band: high
cves:
  - id: CVE-2026-120540
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120540
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch iubenda All-in-one Compliance plugin to latest version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-120540 indicates vulnerability in versions up to 3.13.6
  hunt_leads:
    - lead: Inspect WordPress comment logs for entries containing IUB-COOKIE-BLOCK markers combined with HTML or script tags
      technique_id: T1190
      data_needed:
        - WordPress wp_comments table
        - WAF access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability exploits the improper re-processing of HTML inside IUB-COOKIE-BLOCK markers
  mitigation_plan:
    - priority: immediate
      action: Apply WAF rules to sanitize or block comment submissions containing potential XSS payloads
      owner: SOC
      addresses: CVE-2026-120540
      evidence: Stored XSS vulnerability in WordPress plugin
---

The iubenda All-in-one Compliance for GDPR / CCPA Cookie Consent + more plugin for WordPress (versions <= 3.13.6) is susceptible to stored Cross-Site Scripting (XSS). The vulnerability stems from the `iubendaParser::parse_comments()` function, which uses the `simple_html_dom` library to re-process HTML within `IUB-COOKIE-BLOCK` markers. The library's `remove_noise()` and `restore_noise()` logic replaces specific content (such as `<code>` bodies) with deterministic keys. If the content is restored into an attribute value without re-escaping, an attacker can break out of the attribute context to execute arbitrary JavaScript.

## Attack Chain
1. An unauthenticated attacker submits a WordPress comment containing a malicious payload inside a `<code>` element, wrapped in `IUB-COOKIE-BLOCK` markers.
2. WordPress performs initial KSES filtering on the comment body.
3. The plugin triggers `iubendaParser::parse_comments()` on the saved comment.
4. The `simple_html_dom` library's `remove_noise()` function processes the comment and stores the payload content using a deterministic noise key.
5. The library's `restore_noise()` function later substitutes the noise key back into the output, including into HTML attribute values.
6. The payload, which effectively broke out of the attribute's quote context, is rendered in the page by the server.
7. A victim user (such as an administrator) views the comment, triggering the injected script.

## Impact
Successful exploitation allows unauthenticated attackers to execute arbitrary web scripts in the browser of any user who accesses an affected page, including administrators. This can lead to account takeover, unauthorized actions performed on behalf of the victim, or session theft.

## Recommendation
- Update the "iubenda | All-in-one Compliance for GDPR / CCPA Cookie Consent + more" plugin to the latest version available that incorporates a fix for CVE-2026-120540.
- Implement a Web Application Firewall (WAF) rule to block POST requests containing common XSS vectors or suspicious use of `<` and `>` characters within comment submissions if immediate patching is not possible.
- Audit existing comment sections for unexpected script tags or attribute injections if the plugin has been used extensively on high-traffic sites.
