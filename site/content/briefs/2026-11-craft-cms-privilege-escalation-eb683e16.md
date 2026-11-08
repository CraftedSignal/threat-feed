---
brief_id: brief-2026-11-08-craft-cms-privilege-escalation-eb683e16
event_id: brief-2026-11-08-craft-cms-privilege-escalation-eb683e16
revision: 1
activity_at: "2026-11-08T17:30:07Z"
title: 'Craft CMS: Unauthenticated privilege escalation (CVE-2026-124429)'
slug: 2026-11-craft-cms-privilege-escalation-eb683e16
description: Craft CMS versions 5.0.0 through 5.11.1 contain a privilege escalation vulnerability that allows unauthenticated attackers to hijack deactivated accounts and inherit existing user permissions when email verification is disabled.
date: "2026-11-08T17:30:07Z"
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
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
vendors:
  - Craft CMS
products:
  - Craft CMS (5.0.0-5.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1136.001
    technique_name: Local Account
    evidence: Attackers can register using a deactivated account, set a new password, and inherit permissions stored in userpermissions_users.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078.002
    technique_name: Domain Accounts
    evidence: Due to improper validation, the new registration retains the existing permissions associated with the deactivated account in the userpermissions_users database table.
    confidence_band: high
cves:
  - id: CVE-2026-124429
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124429
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Craft CMS to 5.11.2 or later
      owner: IT Operations
      due: 24h
      evidence: Craft CMS from 5.0.0 before 5.11.2 contains a privilege escalation vulnerability
    - action: Enable email verification for public registrations
      owner: IT Operations
      due: 24h
      evidence: enabling privileged account takeover when email verification is disabled
  hunt_leads:
    - lead: Identify accounts in userpermissions_users associated with recently registered users who have unexpected permissions
      technique_id: T1078
      data_needed:
        - Craft CMS application logs
        - Database records for userpermissions_users
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: the new registration retains the existing permissions associated with the deactivated account in the userpermissions_users database table
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Craft CMS 5.11.2
      owner: IT Operations
      addresses: CVE-2026-124429
      evidence: Craft CMS from 5.0.0 before 5.11.2 contains a privilege escalation vulnerability
---

Craft CMS versions 5.0.0 through 5.11.1 are susceptible to a privilege escalation vulnerability (CVE-2026-124429). The issue occurs when public registration is enabled and email verification is disabled. An attacker can register an account using the identifier of a previously deactivated non-admin account. The application fails to properly re-validate the account status, allowing the newly registered user to inherit existing permissions stored in the userpermissions_users database table.

## Impact

Successful exploitation allows an unauthenticated attacker to perform account takeover of previously deactivated non-admin accounts and gain access to the permissions associated with those accounts.

## Recommendation

* Update Craft CMS to version 5.11.2 or later immediately.
* If patching is delayed, enable email verification for new account registrations to prevent the exploitation of deactivated accounts.
* Review the userpermissions_users database table for accounts with suspicious recent registration dates that retain elevated permissions.
