---
title: Stored XSS Vulnerability in Extendify WordPress Plugin
slug: 2026-10-extendify-xss
description: The Extendify plugin for WordPress is vulnerable to unauthenticated Stored Cross-Site Scripting (XSS) via the 'styles.blocks' parameter, allowing arbitrary script injection.
date: "2026-10-01T06:39:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:extendify:extendify:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - wordpress
  - web-application-vulnerability
vendors:
  - Extendify
products:
  - Extendify (<= 3.1.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-85679
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85679
rules:
  - title: Detects CVE-2026-85679 Exploitation - Unauthenticated XSS in Extendify
    description: Detects potential exploitation attempts targeting the Extendify plugin's REST API endpoint for global styles, where malicious payloads are injected via the styles.blocks parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Extendify plugin to the latest version beyond 3.1.6
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in versions up to 3.1.6
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rule to filter POST/PUT/PATCH requests to /wp/v2/global-styles containing suspicious script tags
      owner: IT Operations
      addresses: CVE-2026-85679
      evidence: Vulnerability allows unauthenticated script injection
---

The Extendify plugin for WordPress (versions 3.1.6 and earlier) contains a critical stored Cross-Site Scripting (XSS) vulnerability stemming from insufficient input sanitization and output escaping within the 'styles.blocks' block type key. The vulnerability is triggered because the `registerIncoming()` function is hooked to `rest_request_before_callbacks`. This causes the vulnerable code path to execute during REST API requests before WordPress performs the necessary permission_callback checks. Consequently, unauthenticated attackers can successfully send malicious POST, PUT, or PATCH requests to the `/wp/v2/global-styles` route to inject arbitrary JavaScript. When a user subsequently views the affected page, the injected scripts execute in the context of the victim's session, potentially leading to administrative account takeover or session hijacking.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a WordPress user's session. This can lead to unauthorized actions performed as the user, administrative account compromise, or the redirection of site visitors to malicious external sites. The scope of impact is limited to users of WordPress sites running the vulnerable Extendify plugin version 3.1.6 or earlier.

## Recommendation

1. Immediately update the Extendify WordPress plugin to a version patched against CVE-2026-85679.
2. Implement a Web Application Firewall (WAF) rule to inspect and block POST, PUT, or PATCH requests to the `/wp/v2/global-styles` endpoint that contain anomalous characters or script tags in the `styles.blocks` parameter.
3. Review web server access logs for requests targeting `/wp/v2/global-styles` with unusual content types or payload structures.
