---
brief_id: brief-2026-11-09-home-assistant-auth
event_id: brief-2026-11-09-home-assistant-auth
revision: 2
activity_at: "2026-11-09T23:18:17Z"
revision_history:
  - revision: 2
    at: "2026-11-09T23:18:17Z"
    checksum: sha256:b572359fc2ae24e00e2edb5a7695cf765318065c54de629a569e2372531ded75
    summary: added coverage for Home Assistant (2026.11.0)
    changed_fields:
      - action_plan
      - affected_products
      - lastmod
      - references
      - severity
      - ttps
      - updates
    source_urls:
      - https://seclists.org/oss-sec/2026/q4/614
title: 'Home Assistant Core: Authentication and session management vulnerabilities'
slug: 2026-11-home-assistant-auth
description: Home Assistant Core 2026.11.0 contains authentication and authorization flaws, including cleartext token storage, non-expiring token classes, and failure to revoke existing sessions upon password reset, facilitating unauthorized long-term access.
date: "2026-11-09T01:11:02Z"
lastmod: "2026-11-09T23:17:08Z"
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
  validation_status: Needs environment validation of token persistence behavior
vendors:
  - Home Assistant
products:
  - Home Assistant Core (2026.11.0)
  - Home Assistant (2026.11.0)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    subtechnique_id: T1550.001
    subtechnique_name: Application Access Token
    evidence: The password is not the key... specific token classes never expire, password change revokes none.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: token secrets in cleartext
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Credentials In Files
    evidence: token secrets in cleartext
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550.002
    technique_name: Pass the Hash
    evidence: two token classes never expire, password change revokes none
    confidence_band: high
references:
  - https://seclists.org/oss-sec/2026/q4/578
  - https://seclists.org/oss-sec/2026/q4/614
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit and purge unrecognized or stale long-lived access tokens via Home Assistant administrative interface
      owner: SOC
      due: 24h
      evidence: Source notes that token secrets are stored in cleartext and never expire, allowing for persistent access
    - action: Identify and audit all active Home Assistant tokens and sessions.
      owner: SOC
      due: 24h
      evidence: two token classes never expire, password change revokes none
  hunt_leads:
    - lead: Identify long-lived access tokens created at unusual times or from unexpected source IPs
      technique_id: T1550.001
      data_needed:
        - Home Assistant audit logs
        - Access logs showing token-based authentication
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Specific token classes never expire, facilitating long-term persistent access
    - lead: Hunt for evidence of unauthorized persistent sessions in Home Assistant logs or configuration files.
      technique_id: T1550.002
      data_needed:
        - Home Assistant authentication/audit logs
        - Configuration files containing token data
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: token secrets in cleartext, two token classes never expire
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the Home Assistant instance to mitigate unauthorized token exploitation
      owner: IT Operations
      addresses: Unauthorized persistent access via token exploitation
      evidence: Source identifies that password changes do not revoke sessions
    - priority: immediate
      action: Restrict network access to Home Assistant management interfaces.
      owner: IT Operations
      addresses: Unauthorized access to authentication tokens
      evidence: Persistent access resulting from non-expiring tokens
  gaps:
    - Lack of native, granular session revocation controls
updates:
  - at: "2026-11-09T23:17:08Z"
    level: L2
    summary: added coverage for Home Assistant (2026.11.0)
    sources:
      - oss-security
    source_urls:
      - https://seclists.org/oss-sec/2026/q4/614
---

Home Assistant Core 2026.11.0 exhibits critical security deficiencies regarding authentication lifecycle management. The vendor documentation emphasizes the strength of passwords; however, technical analysis confirms that the internal implementation fails to treat the password as a primary security boundary. Specifically, token secrets are stored in cleartext, certain token classes do not implement expiration logic, and password change events do not trigger the revocation of active sessions or tokens. These issues allow an attacker who has compromised a token to maintain persistent access even after the user changes their account password.

## Impact

Successful exploitation allows for long-term unauthorized access to the Home Assistant instance, potentially granting control over integrated smart home hardware, including locks, alarm systems, garage doors, and surveillance cameras, as well as access to presence history.

## Recommendation

* Monitor Home Assistant release notes for security patches addressing session management and token storage.
* Audit active long-lived access tokens and sessions within the Home Assistant interface for unauthorized or stale entries.
* Implement network-level restrictions to limit exposure of the Home Assistant interface to untrusted networks until updates are applied.
