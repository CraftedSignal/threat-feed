---
brief_id: brief-2026-11-05-nexus-auth-bypass
event_id: brief-2026-11-05-nexus-auth-bypass
revision: 1
activity_at: "2026-11-05T00:21:29Z"
title: 'Sonatype Nexus Repository 3 Pro: Authentication bypass (CVE-2026-113373)'
slug: 2026-11-nexus-auth-bypass
description: Sonatype Nexus Repository 3 Pro is vulnerable to an authentication bypass (CVE-2026-113373) that allows locked or disabled users to successfully authenticate via SAML or OAuth2/OpenID Connect and gain an active session.
date: "2026-11-05T00:21:29Z"
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
  - cpe:2.3:a:sonatype:nexus_repository_3_pro:*:*:*:*:*:*:*:*
tags:
  - auth-bypass
  - authentication
  - webserver
vendors:
  - Sonatype
products:
  - Nexus Repository 3 Pro
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Sonatype Nexus Repository 3 Pro does not check the local account status when a user signs in through a configured SAML or OAuth2/OpenID Connect identity provider.
    confidence_band: high
cves:
  - id: CVE-2026-113373
    kev_status: "false"
references:
  - https://help.sonatype.com/en/sonatype-nexus-repository-3-98-0-release-notes.html
  - https://support.sonatype.com/hc/en-us/articles/56614238092947/
  - https://sploitus.com/exploit?id=CVE-2026-113373&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Nexus Repository 3 Pro to the version specified in the vendor release notes
      owner: IT Operations
      due: 48h
      evidence: https://help.sonatype.com/en/sonatype-nexus-repository-3-98-0-release-notes.html
  hunt_leads:
    - lead: Identify successful logins for accounts that are currently set to disabled or locked status in the local Nexus user database
      technique_id: T1190
      data_needed:
        - Nexus Repository access logs
        - Nexus Repository audit logs (login events)
        - Local user account status table/database
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: A user whose account was disabled or locked by an administrator in Nexus Repository can sign in again with valid identity provider credentials
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the version provided in the Sonatype release notes for CVE-2026-113373
      owner: IT Operations
      addresses: CVE-2026-113373
      evidence: Vendor advisory documentation
---

Sonatype Nexus Repository 3 Pro fails to validate the local account status of users when authenticating via SAML or OAuth2/OpenID Connect identity providers. An account that has been disabled or locked by an administrator remains able to initiate a session by authenticating against the external identity provider. Upon successful external authentication, the repository grants the user a session with all roles associated with the existing, albeit disabled, local account. This vulnerability allows an attacker possessing valid credentials for the identity provider to bypass account lockout controls.

## Impact

Successful exploitation results in an unauthorized, authenticated session within Nexus Repository 3 Pro with the permissions assigned to the target account. This bypasses organizational policies intended to revoke access for terminated or suspended users.

## Recommendation

- Upgrade to the latest version of Nexus Repository 3 Pro as specified in the official release notes to remediate CVE-2026-113373.
- Audit administrative logs for unusual authentication patterns for accounts previously marked as disabled or locked.
- Review SAML and OAuth2/OpenID Connect configurations for administrative users to ensure local status checks are enforced if supported by the integration.
