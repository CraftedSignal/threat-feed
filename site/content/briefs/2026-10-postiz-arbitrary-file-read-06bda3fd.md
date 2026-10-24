---
brief_id: brief-2026-10-24-postiz-arbitrary-file-read-06bda3fd
event_id: brief-2026-10-24-postiz-arbitrary-file-read-06bda3fd
revision: 3
activity_at: "2026-10-24T20:18:28Z"
revision_history:
  - revision: 2
    at: "2026-10-24T15:15:31Z"
    checksum: sha256:c1c63b72a7cba42c9b63c1b7e8d7ac60e133b3955f43958010631a5f8e0df1a7
    summary: poc_available
    changed_fields:
      - affected_products
      - affected_vendors
      - cpes
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-115932&utm_source=rss&utm_medium=rss
  - revision: 3
    at: "2026-10-24T20:18:28Z"
    checksum: sha256:bc1192964f45c0bcabc6ec563038022792f4cbf6778ac3c6e24b65977d2668e3
    summary: added coverage for Postiz
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
      - https://nvd.nist.gov/vuln/detail/CVE-2026-115933
title: 'Postiz: Arbitrary file read via crafted media path (CVE-2026-115932)'
slug: 2026-10-postiz-arbitrary-file-read-06bda3fd
description: Postiz fails to validate media paths during post creation, allowing users to read arbitrary files from the server disk and exfiltrate them via Discord attachments.
date: "2026-10-24T14:17:02Z"
lastmod: "2026-10-24T20:17:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:gitroom:postiz_app:*:*:*:*:*:*:*:*
  - cpe:2.3:a:postiz:postiz:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-115932&utm_source=rss&utm_medium=rss
tags:
  - authentication-bypass
  - web-application
  - cloud
vendors:
  - Gitroom
  - Postiz
products:
  - postiz-app
  - Postiz
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    subtechnique_id: T1550.003
    subtechnique_name: Pass the Ticket
    evidence: A user could therefore obtain a validly signed token containing any claims they choose, which the application accepts as a session.
    confidence_band: high
cves:
  - id: CVE-2026-115932
    cvss: 9.6
    kev_status: "false"
  - id: CVE-2026-115933
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115932
  - https://sploitus.com/exploit?id=CVE-2026-115932&utm_source=rss&utm_medium=rss
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115933
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review Postiz API logs for requests to credential-refresh and team-invitation endpoints.
      owner: SOC
      due: 24h
      evidence: Source identifies that token generation occurs through specific credential refresh and team-invitation routes.
  hunt_leads:
    - lead: Identify anomalous account privilege changes or session creations originated from external API interactions.
      technique_id: T1550.003
      data_needed:
        - Application API audit logs
        - Authentication logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability allows crafting valid tokens for sessions and organization invitations.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied security patch when available.
      owner: IT Operations
      addresses: CVE-2026-115933
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-10-24T15:14:57Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-115932&utm_source=rss&utm_medium=rss
  - at: "2026-10-24T20:17:57Z"
    level: L2
    summary: added coverage for Postiz
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-115933
---

Postiz is vulnerable to an arbitrary file read (CVE-2026-115932) due to improper input validation. When a post is published, the application treats media paths that are not web addresses as local files on the server's disk without verifying that the file resides within the designated upload directory. An attacker can store a crafted media path with a post to have the publishing worker read an arbitrary file and send it as an attachment to an attacker-controlled Discord server. 

The vulnerability can also be exploited to determine if a file exists on the server and to exhaust backend memory. Because self-registration is open by default, an attacker does not require a pre-existing account to exploit these flaws.
