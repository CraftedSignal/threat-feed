---
brief_id: brief-2026-10-25-parse-server-auth-bypass
event_id: brief-2026-10-25-parse-server-auth-bypass
revision: 1
activity_at: "2026-10-25T14:32:04Z"
title: 'Parse Server: Authentication bypass vulnerability (CVE-2026-116163)'
slug: 2026-10-parse-server-auth-bypass
description: Parse Server versions prior to 8.6.102 and 9.0.0-9.10.5-alpha.2 contain an authentication bypass vulnerability allowing unauthenticated actors to sign up, link identities, or log in as existing users by providing arbitrary authData.
date: "2026-10-25T14:32:04Z"
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
  validation_status: Verified against NVD metadata
cpes:
  - cpe:2.3:a:parseplatform:parse_server:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - web-application
  - cve-2026-116163
vendors:
  - Parse Platform
products:
  - Parse Server (< 8.6.102, 9.0.0 < 9.10.5-alpha.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers can supply arbitrary authData to sign up, link identities, log in as existing users, or skip custom additional authentication factors.
    confidence_band: high
cves:
  - id: CVE-2026-116163
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116163
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Parse Server to 8.6.102 or 9.10.5-alpha.2
      owner: IT Operations
      due: 48h
      evidence: Source states affected versions are before 8.6.102 and 9.10.5-alpha.2
  hunt_leads:
    - lead: Search authentication logs for anomalous authData fields or repeated attempts to link new identities to existing user accounts
      technique_id: T1550
      data_needed:
        - Application logs capturing Parse Server authentication events and authData payloads
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can supply arbitrary authData to sign up or link identities
  mitigation_plan:
    - priority: immediate
      action: Upgrade Parse Server to 8.6.102 or later
      owner: IT Operations
      addresses: CVE-2026-116163
      evidence: NVD vulnerability disclosure
---

Parse Server contains an authentication bypass vulnerability (CVE-2026-116163) affecting custom adapters that subclass 'AuthAdapter'. Due to the failure to trigger the 'validateSetUp', 'validateLogin', and 'validateUpdate' methods, the system incorrectly defaults to accepting any 'authData' provided. This allows remote attackers to perform unauthorized actions including identity linking, account creation, and bypassing custom authentication factors.

## Impact
Successful exploitation allows for unauthorized account creation, account takeover of existing users, and the bypassing of additional authentication mechanisms.

## Recommendation
- Upgrade Parse Server to version 8.6.102 or later.
- For installations using the 9.x branch, upgrade to version 9.10.5-alpha.2 or later.
- Review custom 'AuthAdapter' implementations to identify potential exposure.
- Audit authentication logs for unusual 'authData' payloads or unexpected successful logins originating from non-standard authentication sources.
