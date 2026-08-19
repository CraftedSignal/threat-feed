---
title: Stored Cross-Site Scripting in WP Statistics Plugin
slug: 2026-08-wp-statistics-xss
description: An unauthenticated stored XSS vulnerability in the WP Statistics WordPress plugin allows attackers to inject malicious scripts via the utm_campaign parameter.
date: "2026-08-19T08:13:34Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WP Statistics
products:
  - WP Statistics (14.16.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: The payload can be planted without authentication via the public /wp-statistics/v2/hit REST endpoint.
    confidence_band: med
cves:
  - id: CVE-2026-15780
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15780
rules:
  - title: Detect CVE-2026-15780 Exploitation - Stored XSS Attempt in WP Statistics
    description: Detects exploitation attempts against the WP Statistics plugin by identifying suspicious base64 payloads in the page_uri parameter of the hit REST endpoint.
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
    - action: Patch WP Statistics plugin to version 14.16.9 or higher.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-15780 fix availability.
  mitigation_plan:
    - priority: immediate
      action: Block or filter malicious inputs to the /wp-statistics/v2/hit endpoint at the WAF level.
      owner: IT Operations
      addresses: CVE-2026-15780
      evidence: Vulnerability allows unauthenticated script injection.
---

The WP Statistics plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in all versions up to and including 14.16.8. The vulnerability arises from improper input sanitization and output escaping of the 'utm_campaign' parameter. Attackers can exploit this by sending a crafted request to the public /wp-statistics/v2/hit REST endpoint. Because the plugin logic uses a base64-encoded 'page_uri' parameter that overrides the standard server REQUEST_URI, attackers can bypass existing sanitization mechanisms. This allows for the injection of arbitrary JavaScript which is then stored in the database. When an administrator or authenticated user views the statistics dashboard, the injected script executes within their session context, potentially leading to unauthorized actions or credential theft. This vulnerability is critical for WordPress administrators as it allows unauthenticated, remote exploitation.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the browser of any user who views the statistics dashboard, which typically includes site administrators. This can lead to account takeover, session hijacking, or the distribution of further malicious content to site visitors.

## Recommendation

* Immediately update the WP Statistics plugin to version 14.16.9 or higher to patch CVE-2026-15780.
* Monitor web server logs for POST requests directed to /wp-statistics/v2/hit containing suspicious payloads or high volumes of base64-encoded strings in the 'page_uri' parameter.
* Audit the WP Statistics database tables for injected `<script>` or `onerror` tags within the statistics-related fields.
