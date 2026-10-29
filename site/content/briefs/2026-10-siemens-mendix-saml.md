---
brief_id: brief-2026-10-26-siemens-mendix-saml
event_id: brief-2026-10-26-siemens-mendix-saml
revision: 2
activity_at: "2026-10-29T15:38:20Z"
revision_history:
  - revision: 2
    at: "2026-10-29T15:38:20Z"
    checksum: sha256:c8febaf3558d70cbcb3091d8c26d9958f1a8ee58a18ce18af78ed81cccc6543f
    summary: added CVE-2026-89209
    changed_fields:
      - claim_state
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/news-events/ics-advisories/icsa-26-302-01
title: 'Siemens Mendix SAML: Authentication bypass'
slug: 2026-10-siemens-mendix-saml
description: Siemens has identified an authentication bypass vulnerability in its Mendix SAML module, which could allow unauthenticated attackers to circumvent authentication controls.
date: "2026-10-26T15:52:09Z"
lastmod: "2026-10-29T15:36:47Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified against Siemens security portal
cpes:
  - cpe:2.3:a:siemens:mendix_saml:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - vulnerability
  - industrial-control-systems
vendors:
  - Siemens
products:
  - Mendix SAML (Mendix 10 compatible) (< V4.2.4)
  - Mendix SAML (Mendix 11 compatible) (< V4.2.4)
  - Mendix SAML (Mendix 9 compatible) (< V3.6.29)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The authentication bypass vulnerability in the Mendix SAML module allows unauthenticated attackers to potentially leverage this flaw to bypass authentication controls.
    confidence_band: high
cves:
  - id: CVE-2026-89209
    cvss: 6.8
    epss: 0.00259
    kev_status: "false"
references:
  - https://cyber.gc.ca/en/alerts-advisories/control-systems-siemens-security-advisory-av26-1083
  - https://cert-portal.siemens.com/productcert/html/ssa-137528.html
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-302-01
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch affected Mendix SAML modules to the versions specified in the recommendation section
      owner: IT Operations
      due: 48h
      evidence: Siemens advisory SSA-137528
  hunt_leads:
    - lead: Identify unauthorized access patterns or unexpected login bypass events in Mendix application logs
      technique_id: T1190
      data_needed:
        - Application authentication logs
        - SAML assertion logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows authentication bypass
  mitigation_plan:
    - priority: immediate
      action: Apply security patches to Mendix SAML modules
      owner: IT Operations
      addresses: Authentication bypass vulnerability
      evidence: Siemens SSA-137528
updates:
  - at: "2026-10-29T15:36:47Z"
    level: L2
    summary: added CVE-2026-89209
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/ics-advisories/icsa-26-302-01
---

Siemens has released security advisory SSA-137528 regarding an authentication bypass vulnerability affecting specific versions of the Mendix SAML module. The vulnerability impacts modules compatible with Mendix 9, 10, and 11. Siemens advises users and administrators to update to the patched versions to mitigate the potential for unauthorized access.

## Impact

Successful exploitation could allow an unauthenticated attacker to bypass authentication mechanisms, potentially leading to unauthorized access to affected applications.

## Recommendation

- Upgrade Mendix SAML (Mendix 10 compatible) to V4.2.4 or later.
- Upgrade Mendix SAML (Mendix 11 compatible) to V4.2.4 or later.
- Upgrade Mendix SAML (Mendix 9 compatible) to V3.6.29 or later.
- Review the Siemens security advisory SSA-137528 for additional configuration guidance.
