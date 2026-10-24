---
brief_id: brief-2026-10-24-yudao-cloud-auth-bypass
event_id: brief-2026-10-24-yudao-cloud-auth-bypass
revision: 1
activity_at: "2026-10-24T14:16:37Z"
title: 'yudao-cloud: Authorization bypass in DataPermissionRpcWebFilter (CVE-2026-116016)'
slug: 2026-10-yudao-cloud-auth-bypass
description: An authorization bypass vulnerability in yudao-cloud through 2026.09 allows authenticated users to circumvent row-level data scope restrictions by injecting a header, leading to unauthorized access to cross-departmental and cross-user records.
date: "2026-10-24T14:16:37Z"
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
  validation_status: Needs environment validation of WAF/API gateway blocking capabilities
cpes:
  - cpe:2.3:a:yudao-cloud:yudao-cloud:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - api-security
  - cloud
vendors:
  - yudao-cloud
products:
  - yudao-cloud (<= 2026.09)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can add this header to /admin-api requests, which DataPermissionRpcWebFilter trusts, to read or modify other departments' and users' records within the same tenant.
    confidence_band: high
cves:
  - id: CVE-2026-116016
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116016
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: 'Configure WAF or API gateway to inspect and reject requests to /admin-api that contain the header data-permission-enable: false'
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows authenticated users to evade row-level data scope restrictions by sending a data-permission-enable header set to false.
  hunt_leads:
    - lead: 'Identify authenticated users sending requests to /admin-api with the header data-permission-enable: false'
      technique_id: T1068
      data_needed:
        - Web server access logs or API gateway logs (request headers)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can add this header to /admin-api requests, which DataPermissionRpcWebFilter trusts.
  mitigation_plan:
    - priority: immediate
      action: Apply security vendor patch for CVE-2026-116016
      owner: IT Operations
      addresses: CVE-2026-116016
      evidence: yudao-cloud through 2026.09 contains an authorization bypass vulnerability
---

yudao-cloud versions through 2026.09 contain an authorization bypass vulnerability (CVE-2026-116016). The vulnerability resides in the DataPermissionRpcWebFilter component, which improperly trusts the 'data-permission-enable' HTTP header. Authenticated users can set this header to 'false' to disable row-level data scope restrictions, allowing them to read or modify records belonging to other departments or users within the same tenant.

## Impact

Successful exploitation allows authenticated users to bypass row-level access control, resulting in unauthorized data access or modification of records belonging to other users or departments.

## Recommendation

1. Inventory all instances of yudao-cloud within the environment.
2. Implement an immediate block or strict validation at the API gateway or WAF level to reject requests to /admin-api containing the 'data-permission-enable' header if its value is 'false'.
3. Patch to the latest version of yudao-cloud once an update addressing CVE-2026-116016 is released by the vendor.
4. Monitor application logs for API requests containing the 'data-permission-enable: false' header to identify potential exploitation attempts.
