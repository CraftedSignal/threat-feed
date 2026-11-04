---
brief_id: brief-2026-11-04-databasement-auth-bypass
event_id: brief-2026-11-04-databasement-auth-bypass
revision: 1
activity_at: "2026-11-04T14:47:31Z"
title: 'Databasement: Authentication bypass in OAuthService (CVE-2026-121939)'
slug: 2026-11-databasement-auth-bypass
description: Databasement versions prior to 1.10.9 contain an authentication bypass vulnerability where unverified OIDC emails are linked to local accounts, allowing attackers to assume control of administrative accounts.
date: "2026-11-04T14:47:31Z"
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
  validation_status: Ready for production review
cpes:
  - cpe:2.3:a:databasement:databasement:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - identity-takeover
  - oidc
  - web-security
vendors:
  - Databasement
products:
  - Databasement (< 1.10.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    subtechnique_id: T1550.001
    subtechnique_name: Application Access Token
    evidence: Attackers can register an identity provider account with a victim's unverified email to log in as any user, including the super-admin.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550.001
    technique_name: Application Access Token
    subtechnique_id: T1550.001
    subtechnique_name: Application Access Token
    evidence: Attackers can... retain access after password resets.
    confidence_band: high
cves:
  - id: CVE-2026-121939
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121939
action_plan:
  priority: elevated
  owners:
    - IT Operations
  hunt_leads:
    - lead: Identify unusual OAuth login patterns where the OIDC identity email does not match verified domain ownership or shows rapid account linking activity.
      technique_id: T1550.001
      data_needed:
        - Application identity provider logs
        - Authentication event logs
        - OAuth account linking audit trails
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can register an identity provider account with a victim's unverified email to log in as any user.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Databasement to version 1.10.9 or later.
      owner: IT Operations
      addresses: CVE-2026-121939
      evidence: Databasement before 1.10.9 contains an authentication bypass vulnerability.
---

Databasement before version 1.10.9 contains an authentication bypass vulnerability in the OAuthService::findOrCreateLocalUser() method. The application fails to validate the email_verified claim when linking OIDC identities to local users, allowing an attacker to associate an identity provider account with a victim's email address and authenticate as that user. This allows an attacker to take over any local account, including super-admin accounts, and maintain access even after password resets.

## Impact

Successful exploitation allows for unauthorized authentication as any system user, including accounts with administrative privileges, leading to full account takeover and persistent unauthorized access.

## Recommendation

Update Databasement to version 1.10.9 or later to remediate the vulnerability in OAuthService::findOrCreateLocalUser().
