---
brief_id: brief-2026-11-06-craft-cms-sqli
event_id: brief-2026-11-06-craft-cms-sqli
revision: 4
activity_at: "2026-11-07T02:48:39Z"
revision_history:
  - revision: 2
    at: "2026-11-06T18:34:53Z"
    checksum: sha256:0b0fbc94c561b9143e7f026cc0b548278a1cdf8fbcd1717703b88fbc97e3def5
    summary: new product
    changed_fields:
      - affected_products
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/craft-cms-sqli-priv-esc-nov-2026
  - revision: 3
    at: "2026-11-06T21:58:01Z"
    checksum: sha256:c34c4111842f2c4a30c356659b55434800cd6dfdf5e124e220d93a73d95e7bcc
    summary: poc_available
    changed_fields:
      - affected_products
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=3F28CDCD-865D-5008-9CCA-38DDA5F10928&utm_source=rss&utm_medium=rss
  - revision: 4
    at: "2026-11-07T02:48:39Z"
    checksum: sha256:b73a5f533615025069d090f86fdf75b944306871d88226e1b1cb812f3d1656a4
    summary: new product
    changed_fields:
      - affected_products
      - lastmod
      - updates
    source_urls:
      - https://pwn.watch/i/craft-cms-sqli-priv-esc-nov-2026
title: 'Craft CMS: Unauthenticated SQL injection (CVE-2026-123488)'
slug: 2026-11-craft-cms-sqli
description: Craft CMS versions 4.0.0 through 4.18.8 and 5.0.0 through 5.11.1 contain an unauthenticated SQL injection vulnerability via the element search endpoint that enables remote attackers to perform unauthorized database operations and escalate privileges.
date: "2026-11-06T17:23:34Z"
lastmod: "2026-11-07T02:48:03Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified
cpes:
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=3F28CDCD-865D-5008-9CCA-38DDA5F10928&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - sql-injection
  - cve-2026-123488
vendors:
  - Craft CMS
products:
  - Craft CMS (4.0.0 through 4.18.8)
  - Craft CMS (5.0.0 through 5.11.1)
  - Craft CMS (< 4.18.9)
  - Craft CMS (< 5.11.2)
  - Craft CMS (4.0.0 – 4.18.8)
  - Craft CMS (5.0.0 – 5.11.1)
  - Craft CMS (4.0.0 <= 4.18.8, 5.0.0 <= 5.11.1, 5.8.17 <= 5.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote attackers can read and write the database, setting the admin flag or overwriting password hashes in the users table to gain administrator access.
    confidence_band: high
cves:
  - id: CVE-2026-123488
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123488
  - https://pwn.watch/i/craft-cms-sqli-priv-esc-nov-2026
  - https://github.com/craftcms/cms/security/advisories/GHSA-qcvp-ggx3-97r6
  - https://github.com/craftcms/cms/security/advisories/GHSA-mjj9-pjh4-r48g
  - https://github.com/craftcms/cms/security/advisories/GHSA-f6gf-r952-rxg6
  - https://github.com/craftcms/cms/security/advisories/GHSA-r56r-f696-c8w9
  - https://sploitus.com/exploit?id=3F28CDCD-865D-5008-9CCA-38DDA5F10928&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade vulnerable Craft CMS instances to 4.18.9 or 5.11.2
      owner: IT Operations
      due: 48h
      evidence: Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains an unauthenticated SQL injection
  hunt_leads:
    - lead: Identify HTTP GET/POST requests targeting the element search endpoint containing SQL injection payloads in the attribute parameter.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The element search endpoint because the attribute parameter is concatenated into the query unsanitized
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Craft CMS 4.18.9 or 5.11.2
      owner: IT Operations
      addresses: CVE-2026-123488
      evidence: Fixed versions 4.18.9 and 5.11.2 remediate the injection flaw
updates:
  - at: "2026-11-06T18:34:16Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/craft-cms-sqli-priv-esc-nov-2026
  - at: "2026-11-06T21:57:08Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=3F28CDCD-865D-5008-9CCA-38DDA5F10928&utm_source=rss&utm_medium=rss
  - at: "2026-11-07T02:48:03Z"
    level: L1
    summary: new product
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/craft-cms-sqli-priv-esc-nov-2026
---

Craft CMS versions 4.0.0 through 4.18.8 and 5.0.0 through 5.11.1 are vulnerable to an unauthenticated SQL injection flaw in the element search endpoint. The vulnerability exists due to improper sanitization of the 'attribute' parameter in combination with emulated PDO prepares, which permits stacked SQL queries.

## Impact

An attacker can perform unauthorized read and write operations on the database. This allows for full database compromise, including the ability to overwrite user password hashes or modify administrative flags within the users table to gain persistent administrator access.

## Recommendation

- Upgrade Craft CMS 4.x installations to version 4.18.9 or later.
- Upgrade Craft CMS 5.x installations to version 5.11.2 or later.
- Review web server access logs for anomalous requests to the element search endpoint containing non-standard characters typically used for SQL injection, such as semicolons, comment markers, or SQL keywords in the 'attribute' query parameter.
