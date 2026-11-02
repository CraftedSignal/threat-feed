---
brief_id: brief-2026-11-02-hotgo-auth-bypass
event_id: brief-2026-11-02-hotgo-auth-bypass
revision: 1
activity_at: "2026-11-02T17:49:21Z"
title: 'HotGo: Authentication bypass vulnerability (CVE-2026-120447)'
slug: 2026-11-hotgo-auth-bypass
description: HotGo versions up to 2.15.1 contain an authentication bypass vulnerability allowing unauthenticated attackers to hijack user and administrator accounts via a predictable SMS verification code.
date: "2026-11-02T17:49:21Z"
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
  validation_status: Ready for deployment
cpes:
  - cpe:2.3:a:hotgo:hotgo:*:*:*:*:*:*:*:*
vendors:
  - HotGo
products:
  - HotGo (<= 2.15.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: HotGo through 2.15.1 contains an authentication bypass vulnerability that allows unauthenticated attackers to choose the SMS login verification code
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Attackers who know a user mobile number can set a known code and sign in through /admin/site/mobileLogin to take over accounts
    confidence_band: high
cves:
  - id: CVE-2026-120447
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120447
rules:
  - title: Detect CVE-2026-120447 Exploitation - Authentication Bypass via SMS Code Manipulation
    description: Detects exploitation attempts where an attacker explicitly provides a Code parameter to the /admin/sms/send endpoint
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1556
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all instances of HotGo in the environment
      owner: IT Operations
      due: 24h
      evidence: Vulnerable versions include all releases up to 2.15.1
  mitigation_plan:
    - priority: immediate
      action: Disable the /admin/sms/send endpoint or restrict access until a security patch is available
      owner: IT Operations
      addresses: CVE-2026-120447
      evidence: Vulnerability allows unauthenticated account takeover via the SMS login flow
---

HotGo through version 2.15.1 is affected by an authentication bypass vulnerability. An attacker can manipulate the SMS login process by supplying a user-defined value in the Code field during a request to the /admin/sms/send endpoint. By knowing a target user's mobile number, an attacker can set a known verification code and subsequently authenticate through the /admin/site/mobileLogin endpoint to compromise the account.

## Impact

Successful exploitation allows unauthenticated attackers to gain unauthorized access to any user account, including those with administrative privileges, resulting in full account takeover.

## Recommendation

Identify all HotGo deployments within the environment. As of this report, no specific patch version is listed, but users should monitor the vendor for a security update to address CVE-2026-120447 and apply it immediately upon release.
