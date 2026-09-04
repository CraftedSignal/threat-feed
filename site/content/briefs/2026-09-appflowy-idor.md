---
title: Authorization Bypass in AppFlowy-Cloud
slug: 2026-09-appflowy-idor
description: AppFlowy-Cloud version 0.9.64 is susceptible to an insecure direct object reference (IDOR) vulnerability that allows unauthorized cross-workspace data access and modification.
date: "2026-09-04T15:27:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:appflowy:appflowy_cloud:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
vendors:
  - AppFlowy
products:
  - AppFlowy-Cloud (0.9.64)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can supply a victim's object ID with their own workspace ID to bypass access controls and read, modify, or delete cross-workspace data.
    confidence_band: high
cves:
  - id: CVE-2026-85619
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85619
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade AppFlowy-Cloud to a patched version beyond 0.9.64
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-85619
  mitigation_plan:
    - priority: immediate
      action: Upgrade AppFlowy-Cloud to remediate CVE-2026-85619
      owner: IT Operations
      addresses: CVE-2026-85619
      evidence: NVD vulnerability notice
---

AppFlowy-Cloud version 0.9.64 contains a critical authorization flaw where the application fails to adequately verify that a requested collaborative object is associated with the user's specific workspace. This vulnerability functions as an insecure direct object reference (IDOR), enabling an authenticated attacker to access, modify, or delete sensitive documents and database rows belonging to other workspaces. By manipulating the object ID requests sent to the server, an attacker can bypass intended access controls. The failure to validate ownership at the authorization layer is a significant security concern for multi-tenant environments, as it allows for unauthorized data exfiltration and integrity compromise across organizational boundaries.

## Impact

Successful exploitation allows unauthorized users to read, modify, or delete data stored in any workspace within an AppFlowy-Cloud instance. This leads to total loss of data confidentiality and integrity for targeted workspaces. Impact is high for organizations relying on AppFlowy-Cloud for collaborative documentation and database management.

## Recommendation

Prioritized, concrete actions for teams using AppFlowy-Cloud:

- Identify and audit the use of AppFlowy-Cloud version 0.9.64 within the enterprise environment.
- Upgrade to a secure version of AppFlowy-Cloud that remediates CVE-2026-85619 once provided by the vendor.
- Implement strict egress monitoring on web application traffic to detect unusual access patterns to collaborative object endpoints.
- Configure WAF rules to scrutinize API requests targeting collaborative object IDs that deviate from established user session baselines.
