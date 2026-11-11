---
brief_id: brief-2026-11-11-xapi-timing-side-channel
event_id: brief-2026-11-11-xapi-timing-side-channel
revision: 2
activity_at: "2026-11-11T15:55:21Z"
revision_history:
  - revision: 2
    at: "2026-11-11T15:55:21Z"
    checksum: sha256:abce23985166b9c6e49b665b89b2d9a99dbd4db865d3837c6fff92d15f2d2a0a
    summary: added coverage for Cloud Services Application
    changed_fields:
      - action_plan
      - affected_products
      - affected_vendors
      - claim_state
      - lastmod
      - priority_signals
      - qa_status
      - references
      - severity
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4503
title: 'Xen Project: XAPI Pool Secret comparison vulnerability (CVE-2026-102705)'
slug: 2026-11-xapi-timing-side-channel
description: The Xen Project has disclosed that the XAPI component, which uses a Pool Secret for authenticating requests between hosts in a pool, performs token comparisons using a data-dependent function.
date: "2026-11-11T01:38:26Z"
lastmod: "2026-11-11T15:53:34Z"
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
  credibility: "1"
  rating: A1
  likelihood: unknown
qa_status:
  verdict: pass
  validation_status: Awaiting vendor release for technical validation.
vendors:
  - Xen
  - Ivanti
products:
  - XAPI
  - Cloud Services Application
cves:
  - id: CVE-2026-102705
    kev_status: unknown
references:
  - https://xenbits.xen.org/xsa/advisory-529.html
  - https://seclists.org/oss-sec/2026/q4/641
  - https://www.securityweek.com/citrix-ivanti-patch-critical-and-high-severity-vulnerabilities/
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4503
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory Ivanti Cloud Services Application assets
      owner: IT Operations
      due: 48h
      evidence: Source indicates vulnerability in the named application.
  hunt_leads:
    - lead: Investigate logs for unauthenticated access attempts or unexpected session creation within the Ivanti application interface.
      data_needed:
        - Application access logs
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source states a remote unauthenticated attacker can bypass security.
  mitigation_plan:
    - priority: immediate
      action: Apply forthcoming patches provided by Ivanti
      owner: IT Operations
      addresses: Security bypass vulnerability
      evidence: BSI security advisory.
updates:
  - at: "2026-11-11T15:53:34Z"
    level: L2
    summary: added coverage for Cloud Services Application
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4503
---

Xen Security Advisory XSA-529 identifies that the XAPI component uses a data-dependent comparison function for the Pool Secret, a bearer token used to authenticate requests between hosts in a pool.
