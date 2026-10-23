---
brief_id: brief-2026-10-23-openproject-infoleak
event_id: brief-2026-10-23-openproject-infoleak
revision: 1
activity_at: "2026-10-23T15:03:23Z"
title: 'OpenProject: Information disclosure vulnerability'
slug: 2026-10-openproject-infoleak
description: A remote, authenticated attacker can exploit a vulnerability in OpenProject to disclose sensitive information.
date: "2026-10-23T15:03:23Z"
type: advisory
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
tags:
  - information-disclosure
  - web-application
vendors:
  - OpenProject
products:
  - OpenProject
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4135
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
      action: Apply security patches once the vendor releases version-specific guidance.
      owner: IT Operations
      addresses: OpenProject
      evidence: BSI advisory indicates an information disclosure vulnerability exists.
---

A vulnerability in OpenProject allows a remote, authenticated attacker to disclose sensitive information. The specific nature of the vulnerability and affected versions were not disclosed in the initial advisory. Users are encouraged to monitor for vendor updates regarding this information disclosure flaw.

## Recommendation
- Inventory all instances of OpenProject across the organization.
- Monitor the official OpenProject security advisories for patch releases and version-specific impact details.
- Restrict access to OpenProject instances to trusted users, as the vulnerability requires authentication.
