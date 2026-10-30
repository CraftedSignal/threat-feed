---
brief_id: brief-2026-10-30-opendeepwiki-jwt-key
event_id: brief-2026-10-30-opendeepwiki-jwt-key
revision: 1
activity_at: "2026-10-30T17:35:44Z"
title: 'OpenDeepWiki: Hard-coded JWT signing key vulnerability (CVE-2026-119597)'
slug: 2026-10-opendeepwiki-jwt-key
description: OpenDeepWiki versions up to 2.0.6 include a hard-coded JWT signing key, allowing unauthenticated attackers to forge administrative tokens and gain full application control.
date: "2026-10-30T17:35:44Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:opendeepwiki:opendeepwiki:*:*:*:*:*:*:*:*
tags:
  - authentication
  - web-application
  - cve-2026-119597
vendors:
  - OpenDeepWiki
products:
  - OpenDeepWiki (<= 2.0.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can mint HS256 bearer tokens with an Admin role claim to access /api/admin endpoints.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552.004
    technique_name: Private Keys
    evidence: OpenDeepWiki through 2.0.6 contains a hard-coded JWT signing key vulnerability.
    confidence_band: high
cves:
  - id: CVE-2026-119597
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119597
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Verify all instances of OpenDeepWiki and confirm they are not publicly accessible.
      owner: SOC
      due: 24h
      evidence: Vulnerability allows unauthenticated access via /api/admin endpoints.
  hunt_leads:
    - lead: Identify unauthorized access to /api/admin endpoints
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Application level audit logs for administrative endpoints
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can mint HS256 bearer tokens... to access /api/admin endpoints.
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenDeepWiki to a patched version once released and rotate the Jwt:SecretKey.
      owner: IT Operations
      addresses: CVE-2026-119597
      evidence: OpenDeepWiki through 2.0.6 contains a hard-coded JWT signing key.
---

OpenDeepWiki versions 2.0.6 and earlier contain a critical vulnerability due to a hard-coded JWT signing key ('Jwt:SecretKey') located in the 'appsettings.json' configuration file. This flaw permits unauthenticated remote actors to forge HS256-signed bearer tokens. By asserting an 'Admin' role claim in the forged token, attackers can authenticate to protected '/api/admin' endpoints and perform privileged operations, including user account manipulation, repository modification, and API key management.

## Impact

Successful exploitation results in full administrative compromise of the OpenDeepWiki instance, allowing unauthorized access to all user data, configuration settings, and connected repositories.

## Recommendation

1. Inventory all instances of OpenDeepWiki currently running version 2.0.6 or earlier.
2. Implement an emergency patch or upgrade to the version resolving this vulnerability (if available) or transition the application to an isolated network segment immediately.
3. Rotate the JWT secret immediately upon applying a patch, as the hard-coded key is publicly documented.
4. Hunt for anomalous administrative activity in application logs targeting '/api/admin' routes originating from non-authorized user sessions or unrecognized IP addresses.
