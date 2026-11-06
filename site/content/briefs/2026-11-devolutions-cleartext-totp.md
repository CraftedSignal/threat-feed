---
brief_id: brief-2026-11-06-devolutions-cleartext-totp
event_id: brief-2026-11-06-devolutions-cleartext-totp
revision: 1
activity_at: "2026-11-06T21:29:48Z"
title: 'Devolutions Server: Cleartext storage of TOTP shared secrets (CVE-2026-120733)'
slug: 2026-11-devolutions-cleartext-totp
description: Devolutions Server versions 2026.3.12.0 and earlier store TOTP shared secrets in cleartext, allowing an attacker with database access to extract secrets and compromise MFA.
date: "2026-11-06T21:29:48Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:devolutions:devolutions_server:*:*:*:*:*:*:*:*
vendors:
  - Devolutions
products:
  - Devolutions Server (<= 2026.3.12.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Cleartext storage of sensitive information in the user account data in Devolutions Server 2026.3.12.0 and earlier allows an attacker with read access to the database or a database backup to obtain users TOTP shared secrets.
    confidence_band: high
cves:
  - id: CVE-2026-120733
    cvss: 7.5
    epss: 0.0012
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120733
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Devolutions Server to the version addressing CVE-2026-120733.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-120733 vulnerability notice
  hunt_leads:
    - lead: Identify unauthorized read access to the Devolutions Server database or backup files.
      technique_id: T1552
      data_needed:
        - Database audit logs
        - File system access logs for backups
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows attacker with read access to database or backups to obtain secrets
  mitigation_plan:
    - priority: immediate
      action: Rotate all user TOTP secrets after applying the security update.
      owner: IT Operations
      addresses: CVE-2026-120733
      evidence: Cleartext storage allows access to existing secrets
---

CVE-2026-120733 identifies a security vulnerability in Devolutions Server 2026.3.12.0 and earlier where TOTP shared secrets are stored in cleartext within the user account database. This occurs when an administrator saves a user, causing an unencrypted copy of the security key to be written to the database. An attacker with unauthorized read access to the application database or database backups can extract these secrets to facilitate MFA bypass or unauthorized access.

## Impact

An attacker with read access to the underlying database or database backups can retrieve plaintext TOTP secrets, effectively neutralizing the security provided by multi-factor authentication for affected accounts.

## Recommendation

* Upgrade Devolutions Server to the version containing the fix for CVE-2026-120733.
* Audit access controls for the database and backup locations to ensure only authorized service accounts and administrators have read access.
* Rotate TOTP secrets for all user accounts after patching to mitigate the risk of previously exposed secrets.
* Implement strict database logging to detect unauthorized read access or anomalous query patterns targeting the user account data.
