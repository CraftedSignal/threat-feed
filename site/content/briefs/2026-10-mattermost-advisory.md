---
brief_id: brief-2026-10-29-mattermost-advisory
event_id: brief-2026-10-29-mattermost-advisory
revision: 3
activity_at: "2026-11-04T16:21:43Z"
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
  - revision: 3
    at: "2026-11-04T16:21:43Z"
    checksum: sha256:77db6f2a68d17e40aaa7e269c6beade2c03c19a66ccc17b834c358c713cf76a7
    summary: added coverage for Mattermost Desktop App (< 6.3.1) +4 products
    changed_fields:
      - action_plan
      - affected_products
      - content
      - lastmod
      - references
      - severity
      - summary
      - tags
      - title
      - updates
    source_urls:
      - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1458/
title: Mattermost Desktop App and Server multiple vulnerabilities
slug: 2026-10-mattermost-advisory
description: Multiple undisclosed vulnerabilities in Mattermost Desktop App and Server products have been addressed in recent vendor security bulletins, requiring immediate patching.
date: "2026-10-29T15:52:30Z"
lastmod: "2026-11-04T16:21:08Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
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
  - vulnerability
  - enterprise-software
  - patch-management
vendors:
  - Mattermost
products:
  - Mattermost (<= 11.10.0)
  - Mattermost (<= 11.9.2)
  - Mattermost (<= 11.8.6)
  - Mattermost (<= 11.7.11)
  - Mattermost
  - Mattermost Desktop App (< 6.3.1)
  - Mattermost Desktop App (< 6.2.5)
  - Mattermost Server (11.10.x < 11.10.3)
  - Mattermost Server (11.11.x < 11.11.2)
  - Mattermost Server (11.7.x < 11.7.12)
references:
  - https://cyber.gc.ca/en/alerts-advisories/mattermost-security-advisory-av26-1104
  - https://docs.mattermost.com/security-guide/security-updates
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4258
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1458/
  - https://mattermost.com/security-updates/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
    - SOC
  immediate_actions:
    - action: Inventory Mattermost deployments and prepare for version upgrades
      owner: IT Operations
      due: 24h
      evidence: CCCS advisory AV26-1104 recommends applying necessary updates
    - action: Patch Mattermost Server and Desktop App installations to the documented secure versions
      owner: IT Operations
      due: 48h
      evidence: Source advises referring to vendor security bulletins for patches
  mitigation_plan:
    - priority: immediate
      action: Patch Mattermost instances to the latest secure version once released
      owner: IT Operations
      addresses: Mattermost versions <= 11.10.0
      evidence: Mattermost security advisory AV26-1104
    - priority: immediate
      action: Upgrade Mattermost Server and Desktop App to the versions specified in MMSA-2026-00800, MMSA-2026-00767, MMSA-2026-00770, and MMSA-2026-00804
      owner: IT Operations
      addresses: Mattermost Desktop and Server vulnerabilities
      evidence: Source lists specific version thresholds for remediation
updates:
  - at: "2026-10-30T15:06:19Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4258
  - at: "2026-11-04T16:21:08Z"
    level: L2
    summary: added coverage for Mattermost Desktop App (< 6.3.1) +4 products
    sources:
      - anssi
    source_urls:
      - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1458/
---

The French National Cybersecurity Agency (ANSSI) has issued an advisory regarding multiple vulnerabilities identified in Mattermost Desktop App and Server products. The specific nature of these vulnerabilities and their technical impact remain undisclosed by the vendor. Administrators should consult the referenced Mattermost security bulletins (MMSA-2026-00800, MMSA-2026-00767, MMSA-2026-00770, and MMSA-2026-00804) to obtain and deploy the necessary patches.

## Recommendation

- Perform an inventory of all Mattermost Desktop App and Server installations across the organization.
- Patch Mattermost Desktop App to version 6.3.1 or higher (for the 6.3.x branch).
- Patch Mattermost Desktop App to version 6.2.5 or higher (for the 6.x branch).
- Patch Mattermost Server to versions 11.10.3, 11.11.2, or 11.7.12 as appropriate for the installed version.
- Review the Mattermost official security updates page for further technical details as they become available.
