---
title: Memos Refresh Token Revocation Failure
slug: 2026-09-memos-token-revocation
description: Memos versions 0.26.0 through 0.30.0 fail to invalidate refresh tokens after a password change, enabling persistent unauthorized access via the RefreshToken RPC.
date: "2026-09-01T17:07:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:usememos:memos:0.26.0:*:*:*:*:*:*:*
  - cpe:2.3:a:usememos:memos:0.30.0:*:*:*:*:*:*:*
tags:
  - session-management
  - vulnerability
  - mssql-bypass
vendors:
  - UseMemos
products:
  - Memos (0.26.0 - 0.30.0)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An attacker with a stolen refresh token can call the RefreshToken RPC to obtain new access tokens and rotate the refresh token indefinitely, bypassing the password change security measure.
    confidence_band: high
cves:
  - id: CVE-2026-84203
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84203
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Memos to version 0.30.1 or later to resolve CVE-2026-84203.
      owner: IT Operations
      due: 48h
      evidence: Source confirms Memos versions 0.26.0 through 0.30.0 fail to revoke refresh tokens.
  mitigation_plan:
    - priority: immediate
      action: Manually force a global session invalidation if unauthorized access is suspected, as password changes are insufficient.
      owner: IT Operations
      addresses: CVE-2026-84203
      evidence: Memos fails to revoke refresh tokens when a user changes their password.
---

Memos versions 0.26.0 through 0.30.0 contain a critical session management vulnerability where the application fails to revoke existing refresh tokens upon a user password change. This security flaw means that if an attacker has already obtained a valid refresh token through previous compromise or session hijacking, they can continue to use that token to authenticate against the RefreshToken RPC endpoint. By repeatedly calling this RPC, the attacker can generate new access tokens and rotate the refresh token indefinitely, effectively bypassing the security intent of a password reset. This persistence mechanism allows an unauthorized actor to maintain account access long after the legitimate user believes they have secured their account by changing their credentials. Defenders should identify any anomalous RefreshToken RPC activity originating from sessions that predate recent password changes.

## Impact

Successful exploitation allows an attacker to maintain persistent unauthorized access to affected Memos instances, bypassing account password changes. This impact spans all Memos deployments within the 0.26.0 to 0.30.0 range, affecting data integrity and confidentiality for all users within the environment. If compromised, attackers may gain continuous access to sensitive notes and stored information within the Memos platform without needing the current user password.

## Recommendation

1. Upgrade all Memos instances to a version later than 0.30.0 immediately to address the session management defect identified in CVE-2026-84203.
2. Perform a global session revocation if suspicious activity is detected, as simple password resets will not invalidate existing sessions in affected versions.
3. Audit webserver access logs for anomalous, high-frequency calls to the RefreshToken RPC endpoint that may indicate automated token rotation by an unauthorized actor.
