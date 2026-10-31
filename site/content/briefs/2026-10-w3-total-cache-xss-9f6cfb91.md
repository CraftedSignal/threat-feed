---
brief_id: brief-2026-10-29-w3-total-cache-xss-9f6cfb91
event_id: brief-2026-10-29-w3-total-cache-xss-9f6cfb91
revision: 2
activity_at: "2026-10-31T07:53:50Z"
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
title: 'Bold Grid W3 Total Cache: Stored Cross-site Scripting (CVE-2026-114178)'
slug: 2026-10-w3-total-cache-xss-9f6cfb91
description: Bold Grid W3 Total Cache versions from n/a through 2.10.7 contain an Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability, which allows Stored XSS.
date: "2026-10-29T20:01:23Z"
lastmod: "2026-10-31T07:52:06Z"
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
cves:
  - id: CVE-2026-114178
    cvss: 7.1
    epss: 0.00205
    kev_status: "false"
  - id: CVE-2026-111254
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114178
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111254
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
  hunt_leads:
    - lead: Inspect comment database tables for injected <script> tags or encoded malicious JavaScript patterns
      technique_id: T1190
      data_needed:
        - WordPress database comment table (wp_comments)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves stored XSS via the comment parameter
  mitigation_plan:
    - priority: immediate
      action: Disable Disk Enhanced page caching if Pro license is inactive
      owner: IT Operations
      addresses: CVE-2026-111254
      evidence: Exploitation requires Disk Enhanced page caching remains configured
updates:
  - at: "2026-10-31T07:52:06Z"
    level: L2
    summary: added coverage for W3 Total Cache (<= 2.10.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111254
---

Bold Grid W3 Total Cache is affected by an Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability. The issue allows Stored XSS and affects versions from n/a through 2.10.7.

## Technical Details
- Vulnerability Type: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- Impact: Stored XSS
- CVSS v3.1 Base Score: 7.1
