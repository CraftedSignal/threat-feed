---
brief_id: brief-2026-10-29-freemail-auth-bypass
event_id: brief-2026-10-29-freemail-auth-bypass
revision: 1
activity_at: "2026-10-29T15:37:30Z"
title: 'FreeMail: Authorization bypass in /api/create (CVE-2026-119049)'
slug: 2026-10-freemail-auth-bypass
description: FreeMail versions before 5.3.2 contain an authorization bypass vulnerability allowing authenticated users to claim ownership of other mailboxes via the assignMailboxToUser functionality.
date: "2026-10-29T15:37:30Z"
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
  validation_status: Ready for production; no specific environment validation required beyond vendor update verification.
cpes:
  - cpe:2.3:a:freemail:freemail:*:*:*:*:*:*:*:*
vendors:
  - FreeMail
products:
  - FreeMail (< 5.3.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: FreeMail before 5.3.2 contains an authorization bypass vulnerability that allows authenticated users to claim another users existing mailbox.
    confidence_band: high
cves:
  - id: CVE-2026-119049
    cvss: 7.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119049
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch FreeMail to version 5.3.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability remediation requires upgrading to version 5.3.2 or later.
  hunt_leads:
    - lead: Monitor web access logs for high volumes of POST requests to /api/create, particularly those utilizing the assignMailboxToUser functionality.
      technique_id: T1078
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can become co-owners through assignMailboxToUser.
  mitigation_plan:
    - priority: immediate
      action: Upgrade FreeMail to version 5.3.2.
      owner: IT Operations
      addresses: CVE-2026-119049
      evidence: FreeMail before 5.3.2 contains an authorization bypass.
---

FreeMail versions prior to 5.3.2 are susceptible to an authorization bypass vulnerability within the /api/create endpoint. An authenticated attacker can leverage the assignMailboxToUser function to associate an existing, victim-owned mailbox with their own account. This unauthorized association grants the attacker the ability to read messages, intercept verification codes, modify mail forwarding settings, and delete arbitrary messages from the compromised mailbox.

## Impact
Successful exploitation results in full unauthorized access to a victim's mailbox. Potential impact includes account takeovers via password resets (due to interception of verification codes) and exfiltration of sensitive communications.

## Recommendation
- Upgrade FreeMail to version 5.3.2 or later immediately.
- Audit logs for the /api/create endpoint to identify anomalous mailbox assignment patterns, specifically multiple associations for the same mailbox identifier.
