---
brief_id: brief-2026-10-23-openproject-infoleak
event_id: brief-2026-10-23-openproject-infoleak
revision: 2
activity_at: "2026-10-29T11:02:33Z"
revision_history:
  - revision: 2
    at: "2026-10-29T11:02:33Z"
    checksum: sha256:c078c7f61272608adb64b3c726a27f5805a546b8aad7a282d6c699c819e2cf55
    summary: poc_available; added CVE-2026-52782; openproject version < 17.3.3
    changed_fields:
      - action_plan
      - affected_products
      - claim_state
      - cpes
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ABRAXAS-CVE-2026-52782&utm_source=rss&utm_medium=rss
title: 'OpenProject: Information disclosure vulnerability'
slug: 2026-10-openproject-infoleak
description: A remote, authenticated attacker can exploit a vulnerability in OpenProject to disclose sensitive information.
date: "2026-10-23T15:03:23Z"
lastmod: "2026-10-29T11:01:41Z"
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
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:openproject:openproject:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ABRAXAS-CVE-2026-52782&utm_source=rss&utm_medium=rss
tags:
  - information-disclosure
  - web-application
vendors:
  - OpenProject
products:
  - OpenProject (< 17.3.3)
cves:
  - id: CVE-2026-52782
    cvss: 9.9
    epss: 0.00454
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4135
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ABRAXAS-CVE-2026-52782&utm_source=rss&utm_medium=rss
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
    - Detection Engineering
  enrichment_needed:
    - item: Affected versions
      owner: CTI
      reason: Current advisory lacks version scope to determine patch urgency.
      evidence: Source is silent on specific affected versions.
  mitigation_plan:
    - priority: medium_term
      action: Patch OpenProject to 17.3.3 or later
      owner: IT Operations
      addresses: OpenProject
      evidence: BSI advisory indicates an information disclosure vulnerability exists.
updates:
  - at: "2026-10-29T11:01:41Z"
    level: L2
    summary: poc_available; added CVE-2026-52782; openproject version < 17.3.3
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ABRAXAS-CVE-2026-52782&utm_source=rss&utm_medium=rss
---

A vulnerability in OpenProject allows a remote, authenticated attacker to disclose sensitive information. The specific nature of the vulnerability and affected versions were not disclosed in the initial advisory. Users are encouraged to monitor for vendor updates regarding this information disclosure flaw.

## Recommendation
- Inventory all instances of OpenProject across the organization.
- Monitor the official OpenProject security advisories for patch releases and version-specific impact details.
- Restrict access to OpenProject instances to trusted users, as the vulnerability requires authentication.
