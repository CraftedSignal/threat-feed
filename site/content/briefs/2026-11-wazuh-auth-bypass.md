---
brief_id: brief-2026-11-06-wazuh-auth-bypass
event_id: brief-2026-11-06-wazuh-auth-bypass
revision: 1
activity_at: "2026-11-06T17:23:39Z"
title: 'Wazuh Dashboard: Authorization bypass in /api/request proxy (CVE-2026-112340)'
slug: 2026-11-wazuh-auth-bypass
description: An authorization bypass vulnerability in Wazuh dashboard versions 4.9.0 to 4.14.8 allows authenticated users to override Manager API Authorization headers via the /api/request endpoint.
date: "2026-11-06T17:23:39Z"
type: advisory
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
cpes:
  - cpe:2.3:a:wazuh:wazuh_dashboard:*:*:*:*:*:*:*:*
tags:
  - web-application
  - vulnerability
  - authentication-bypass
  - privilege-escalation
vendors:
  - Wazuh
products:
  - Wazuh dashboard (4.9.0 - 4.14.8)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Attackers can supply nested body.headers.Authorization values that replace the server-side session Bearer token, letting them act as another Manager API identity.
    confidence_band: high
cves:
  - id: CVE-2026-112340
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112340
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Wazuh dashboard to version 4.14.9 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-112340 remediation
  hunt_leads:
    - lead: Identify abnormal Authorization header usage in dashboard proxy requests
      technique_id: T1548
      data_needed:
        - Wazuh dashboard web access logs
        - Application proxy logs for /api/request
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows overriding of Manager API Authorization header via the /api/request proxy endpoint.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 4.14.9
      owner: IT Operations
      addresses: CVE-2026-112340
      evidence: Wazuh dashboard advisory
---

Wazuh dashboard plugins in versions 4.9.0 through 4.14.8 contain an authorization bypass vulnerability (CVE-2026-112340) in the /api/request proxy endpoint. An authenticated user can supply a nested body.headers.Authorization value within a request, causing the dashboard to overwrite the server-side session Bearer token. This allows the attacker to impersonate other Manager API identities or submit unauthenticated requests to the backend API.

## Impact

Successful exploitation allows an authenticated user to perform unauthorized actions with the privileges of another user or unauthenticated service account within the Wazuh Manager API, potentially leading to unauthorized system configuration changes or data access.

## Recommendation

- Upgrade the Wazuh dashboard to version 4.14.9 or later to remediate CVE-2026-112340.
- Audit logs for the /api/request endpoint to identify potential abuse of the authorization header modification.
- Implement strict access controls for dashboard users to limit the potential impact of authenticated privilege escalation.
