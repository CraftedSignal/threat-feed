---
brief_id: brief-2026-10-25-ruoyi-vue-pro-auth-bypass
event_id: brief-2026-10-25-ruoyi-vue-pro-auth-bypass
revision: 1
activity_at: "2026-10-25T04:26:01Z"
title: 'YunaiV ruoyi-vue-pro: Improper authentication in SMS Code Verification (CVE-2026-116006)'
slug: 2026-10-ruoyi-vue-pro-auth-bypass
description: An improper authentication vulnerability in the SMS Code Verification component of ruoyi-vue-pro allows remote attackers to bypass authentication mechanisms by manipulating the mobile or code arguments in AuthController.java.
date: "2026-10-25T04:26:01Z"
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
  - cpe:2.3:a:yunaiv:ruoyi-vue-pro:*:*:*:*:*:*:*:*
vendors:
  - YunaiV
products:
  - ruoyi-vue-pro (<= 2026.09)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1589.001
    technique_name: Credentials
    evidence: The manipulation of the argument mobile/code results in improper authentication.
    confidence_band: high
cves:
  - id: CVE-2026-116006
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116006
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Identify and isolate internet-facing instances of ruoyi-vue-pro version 2026.09 or earlier.
      owner: SOC
      due: 24h
      evidence: Vulnerability in ruoyi-vue-pro up to 2026.09.
  hunt_leads:
    - lead: Hunt for spikes in authentication failures or rapid, sequential code attempts for a single mobile number in application logs.
      technique_id: T1589.001
      data_needed:
        - Application audit logs or web server access logs detailing POST requests to SMS verification endpoints
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Manipulation of the argument mobile/code results in improper authentication.
  mitigation_plan:
    - priority: immediate
      action: Apply compensating controls by implementing rate limiting on the SMS verification endpoint.
      owner: IT Operations
      addresses: CVE-2026-116006
      evidence: The manipulation of the argument mobile/code results in improper authentication.
---

A vulnerability exists in the SMS Code Verification component of ruoyi-vue-pro (versions up to 2026.09). An attacker can exploit this remotely by manipulating the `mobile` or `code` parameters processed by `AuthController.java` to perform improper authentication. Public exploit code is available for this vulnerability. The vendor has been unresponsive to disclosure efforts.

## Impact
Successful exploitation allows for improper authentication, potentially granting unauthorized access to the application.

## Recommendation
- Inventory all instances of ruoyi-vue-pro version 2026.09 or earlier.
- Implement strict rate limiting and monitoring on the SMS code verification endpoint handled by `AuthController.java` to detect anomalous authentication attempts.
- Prioritize application-level logging for all authentication-related requests, specifically tracking the frequency and validity of SMS verification codes associated with specific mobile numbers.
