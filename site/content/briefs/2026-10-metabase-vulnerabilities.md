---
brief_id: brief-2026-10-28-metabase-vulnerabilities
event_id: brief-2026-10-28-metabase-vulnerabilities
revision: 1
activity_at: "2026-10-28T17:43:39Z"
title: 'Metabase: Multiple vulnerabilities in Pro, Enterprise, and open-source versions'
slug: 2026-10-metabase-vulnerabilities
description: Metabase has released security updates for multiple unspecified vulnerabilities affecting Pro, Enterprise, and open-source editions, requiring an upgrade to version 0.64.3.4 or 1.64.3.4.
date: "2026-10-28T17:43:39Z"
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
  validation_status: Pending inventory check
tags:
  - vulnerability
  - webserver
  - informational
vendors:
  - Metabase
products:
  - Metabase (< 0.64.3.4)
  - Metabase Pro (< 1.64.3.4)
  - Metabase Enterprise (< 1.64.3.4)
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1403/
  - https://github.com/metabase/metabase/security/advisories/GHSA-v44v-x8x4-mvcw
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Metabase instances to version 0.64.3.4 or 1.64.3.4
      owner: IT Operations
      due: 48h
      evidence: Source advisory states Metabase versions prior to 0.64.3.4 and 1.64.3.4 are affected
  mitigation_plan:
    - priority: immediate
      action: Patch all Metabase instances to 0.64.3.4 or 1.64.3.4
      owner: IT Operations
      addresses: Multiple unspecified vulnerabilities in Metabase
      evidence: Vendor security advisory GHSA-v44v-x8x4-mvcw
---

Multiple vulnerabilities have been identified in Metabase. The vendor has released security patches to address these issues, which were disclosed in GHSA-v44v-x8x4-mvcw. The nature of the vulnerabilities remains undisclosed by the manufacturer. Users must upgrade to versions 0.64.3.4 (open-source) or 1.64.3.4 (Pro/Enterprise) to remediate the potential security risk.

## Recommendation

* Identify all instances of Metabase in the environment and determine if they are running a version prior to 0.64.3.4 or 1.64.3.4.
* Apply the updates to Metabase, Metabase Pro, and Metabase Enterprise to reach version 0.64.3.4 or 1.64.3.4 immediately.
* Review the vendor's security advisory GHSA-v44v-x8x4-mvcw for any additional post-patch configuration requirements.
