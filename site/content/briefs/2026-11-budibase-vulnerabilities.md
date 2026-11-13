---
brief_id: brief-2026-11-13-budibase-vulnerabilities
event_id: brief-2026-11-13-budibase-vulnerabilities
revision: 1
activity_at: "2026-11-13T16:07:24Z"
title: 'Budibase: Multiple vulnerabilities'
slug: 2026-11-budibase-vulnerabilities
description: Budibase is susceptible to multiple vulnerabilities that allow an attacker to perform unauthorized file manipulation, information disclosure, security control bypass, or initiate a denial-of-service condition.
date: "2026-11-13T16:07:24Z"
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
  verdict: pass_with_fixes
  validation_status: Awaiting vendor release of specific CVE identifiers and patch versions.
vendors:
  - Budibase
products:
  - Budibase
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4567
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory Budibase deployments in the environment.
      owner: IT Operations
      due: 24h
  hunt_leads:
    - lead: Investigate web server logs for suspicious requests involving unexpected file path manipulation or anomalous input patterns indicative of unauthorized access attempts.
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source documentation indicates vulnerabilities allow file manipulation and security bypass.
  mitigation_plan:
    - priority: short_term
      action: Apply security patches as soon as they are published by Budibase.
      owner: IT Operations
      addresses: Multiple vulnerabilities in Budibase
      evidence: BSI advisory WID-SEC-2026-4567
---

Budibase is impacted by multiple vulnerabilities that enable an attacker to perform unauthorized file manipulation, information disclosure, security control bypass, and initiate denial-of-service conditions. Specific CVEs and affected versions have not been disclosed in the initial advisory.

## Recommendation

- Identify and inventory all instances of Budibase within the environment.
- Monitor official vendor channels and the BSI advisory for specific versioning details and patch availability.
- Restrict network access to Budibase instances until patches are applied.
