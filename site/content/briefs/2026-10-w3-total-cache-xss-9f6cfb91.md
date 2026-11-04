---
brief_id: brief-2026-10-29-w3-total-cache-xss-9f6cfb91
event_id: brief-2026-10-29-w3-total-cache-xss-9f6cfb91
revision: 3
activity_at: "2026-11-04T23:09:49Z"
revision_history:
  - revision: 2
    at: "2026-10-31T07:53:50Z"
    checksum: sha256:844f023e13ded86b99ccf47c7b1107953c127ece5ec15766d5f77e943a64c902
    summary: added coverage for W3 Total Cache (<= 2.10.7)
    changed_fields:
      - action_plan
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - lastmod
      - qa_status
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111254
  - revision: 3
    at: "2026-11-04T23:09:49Z"
    checksum: sha256:9b9f45b797c7962972379bbd8d4bf4c75b49a1809c6a7cad13fc1148fb8e786b
    summary: added coverage for W3 Total Cache (<= 2.10.7)
    changed_fields:
      - action_plan
      - cves
      - lastmod
      - priority_signals
      - references
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=10FEF046-5D63-5161-A2EC-6F09BEEA5920&utm_source=rss&utm_medium=rss
title: 'Bold Grid W3 Total Cache: Stored Cross-site Scripting (CVE-2026-114178)'
slug: 2026-10-w3-total-cache-xss-9f6cfb91
description: Bold Grid W3 Total Cache versions from n/a through 2.10.7 contain an Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability, which allows Stored XSS.
date: "2026-10-29T20:01:23Z"
lastmod: "2026-11-04T23:09:11Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source-supported findings validated
cpes:
  - cpe:2.3:a:bold_grid:w3_total_cache:*:*:*:*:*:*:*:*
  - cpe:2.3:a:boldgrid:w3_total_cache:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - xss
  - web-application
  - cve-2026-111254
vendors:
  - Bold Grid
  - BoldGrid
products:
  - W3 Total Cache (n/a through 2.10.7)
  - W3 Total Cache (<= 2.10.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: Injection served from the page cache to a fresh anonymous GET (stored, not one-shot).
    confidence_band: high
cves:
  - id: CVE-2026-114178
    cvss: 7.1
    epss: 0.00205
    kev_status: "false"
  - id: CVE-2026-111254
    cvss: 7.2
    kev_status: "false"
  - id: CVE-2026-120019
    cvss: 5.4
    epss: 0.00221
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114178
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111254
  - https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/w3-total-cache/w3-total-cache-2107-unauthenticated-stored-cross-site-scripting-via-comment-content-via-predictable-minify-placeholder
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120019
  - https://sploitus.com/exploit?id=10FEF046-5D63-5161-A2EC-6F09BEEA5920
  - https://sploitus.com/exploit?id=10FEF046-5D63-5161-A2EC-6F09BEEA5920&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update W3 Total Cache to the latest version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-111254 vulnerability present in versions <= 2.10.7
    - action: Patch W3 Total Cache to version 2.11.0 or later.
      owner: IT Operations
      due: 24h
      evidence: 2.11.0 replaces the namespace with CSPRNG output and extends it while it occurs anywhere in the source HTML.
  hunt_leads:
    - lead: Inspect comment database tables for injected <script> tags or encoded malicious JavaScript patterns
      technique_id: T1190
      data_needed:
        - WordPress database comment table (wp_comments)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves stored XSS via the comment parameter
    - lead: Hunt for suspicious comment submissions containing HTML comment syntax or suspicious attribute strings (e.g., autofocus, onfocus) in raw comment text.
      technique_id: T1190
      data_needed:
        - Web server logs
        - WordPress database comments table
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The PoC posts inert comments that contain injected markup (event-handler attributes) spliced into an anchor context.
  mitigation_plan:
    - priority: immediate
      action: Disable Disk Enhanced page caching if Pro license is inactive
      owner: IT Operations
      addresses: CVE-2026-111254
      evidence: Exploitation requires Disk Enhanced page caching remains configured
    - priority: immediate
      action: Disable HTML minification settings in W3 Total Cache.
      owner: IT Operations
      addresses: CVE-2026-120019
      evidence: The pipeline runs minify_html() over every HTML page render (Minify_Plugin.php:367-371).
updates:
  - at: "2026-10-31T07:52:06Z"
    level: L2
    summary: added coverage for W3 Total Cache (<= 2.10.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111254
  - at: "2026-11-04T23:09:11Z"
    level: L2
    summary: added coverage for W3 Total Cache (<= 2.10.7)
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=10FEF046-5D63-5161-A2EC-6F09BEEA5920&utm_source=rss&utm_medium=rss
---

Bold Grid W3 Total Cache is affected by an Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability. The issue allows Stored XSS and affects versions from n/a through 2.10.7.

## Technical Details
- Vulnerability Type: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- Impact: Stored XSS
- CVSS v3.1 Base Score: 7.1
