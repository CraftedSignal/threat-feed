---
brief_id: brief-2026-10-29-mattermost-advisory
event_id: brief-2026-10-29-mattermost-advisory
revision: 2
activity_at: "2026-10-30T15:08:44Z"
revision_history:
  - revision: 2
    at: "2026-10-30T15:08:44Z"
    checksum: sha256:32950237ea64b7e2473ef8b5006ae871a3d274281ff6f0183c6f8953fe8b2bbf
    summary: new product
    changed_fields:
      - affected_products
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4258
title: Mattermost Security Updates (AV26-1104)
slug: 2026-10-mattermost-advisory
description: Mattermost has released a security advisory addressing multiple vulnerabilities affecting versions up to 11.10.0 and earlier maintenance releases.
date: "2026-10-29T15:52:30Z"
lastmod: "2026-10-30T15:06:19Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "6"
  rating: A6
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Verified against CCCS advisory metadata
tags:
  - vulnerability-management
  - security-advisory
vendors:
  - Mattermost
products:
  - Mattermost (<= 11.10.0)
  - Mattermost (<= 11.9.2)
  - Mattermost (<= 11.8.6)
  - Mattermost (<= 11.7.11)
  - Mattermost
references:
  - https://cyber.gc.ca/en/alerts-advisories/mattermost-security-advisory-av26-1104
  - https://docs.mattermost.com/security-guide/security-updates
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4258
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory Mattermost deployments and prepare for version upgrades
      owner: IT Operations
      due: 24h
      evidence: CCCS advisory AV26-1104 recommends applying necessary updates
  mitigation_plan:
    - priority: immediate
      action: Patch Mattermost instances to the latest secure version once released
      owner: IT Operations
      addresses: Mattermost versions <= 11.10.0
      evidence: Mattermost security advisory AV26-1104
updates:
  - at: "2026-10-30T15:06:19Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4258
---

The Canadian Centre for Cyber Security (CCCS) has issued an advisory regarding security vulnerabilities in Mattermost. The affected versions include releases up to and including 11.10.0, 11.9.2, 11.8.6, and 11.7.11. As of the time of publication, technical details regarding the specific nature of the vulnerabilities remain undisclosed in the CCCS advisory. Users and administrators are advised to monitor the official Mattermost Security Updates portal for patches.

## Recommendation

- Inventory all Mattermost server instances within the environment.
- Review the Mattermost Security Updates documentation for specific vulnerability details and patch availability.
- Apply the latest security patches to all affected versions (11.10.0 and earlier) immediately upon release.
