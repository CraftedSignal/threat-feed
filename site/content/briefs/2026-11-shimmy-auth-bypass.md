---
brief_id: brief-2026-11-10-shimmy-auth-bypass
event_id: brief-2026-11-10-shimmy-auth-bypass
revision: 1
activity_at: "2026-11-10T02:08:03Z"
title: 'Michael-A-Kuykendall Shimmy: Missing authentication in Inference API (CVE-2026-125087)'
slug: 2026-11-shimmy-auth-bypass
description: The Michael-A-Kuykendall Shimmy Inference API contains a missing authentication vulnerability in src/server.rs that permits unauthenticated remote access, resolved in version 2.6.5.
date: "2026-11-10T02:08:03Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:michael-a-kuykendall:shimmy:*:*:*:*:*:*:*:*
vendors:
  - Michael-A-Kuykendall
products:
  - Shimmy (<= 2.6.4)
cves:
  - id: CVE-2026-125087
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125087
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Shimmy to version 2.6.5 or later
      owner: IT Operations
      due: 48h
      evidence: The patch is named 3f2ee748c02eeb229987913fe289a2ed9a24595d. You should upgrade the affected component.
  hunt_leads:
    - lead: Monitor web server access logs for anomalous, unauthenticated requests to the Inference API
      data_needed:
        - Web server access logs (HTTP status codes, request paths)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The affected element is an unknown function of the file src/server.rs of the component Inference API.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Shimmy 2.6.5
      owner: IT Operations
      addresses: CVE-2026-125087
      evidence: Upgrading to version 2.6.5 is sufficient to fix this issue.
---

A missing authentication vulnerability exists in the Michael-A-Kuykendall Shimmy component, specifically within the Inference API's handling of requests in the `src/server.rs` file. This vulnerability allows an unauthenticated remote attacker to interact with the API functions. This flaw affects versions up to 2.6.4. The issue is addressed in version 2.6.5.

## Impact

Successful exploitation allows for unauthenticated remote interaction with the Inference API, which may lead to unauthorized data access or service manipulation depending on the API's function capabilities.

## Recommendation

* Upgrade Shimmy to version 2.6.5 or later immediately.
* Audit logs for unauthorized access patterns to the Inference API endpoints.
* Implement network-level access controls to restrict exposure of the Inference API to authorized clients only.
