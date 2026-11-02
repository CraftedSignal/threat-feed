---
brief_id: brief-2026-11-02-ape-volo-admin-auth-bypass
event_id: brief-2026-11-02-ape-volo-admin-auth-bypass
revision: 1
activity_at: "2026-11-02T15:47:26Z"
title: 'ape-volo-admin: Authentication bypass via hardcoded JWT signing key (CVE-2026-120442)'
slug: 2026-11-ape-volo-admin-auth-bypass
description: An authentication bypass vulnerability in ape-volo-admin before version 3.6.1 allows unauthenticated attackers to forge administrative tokens using a hardcoded JWT signing key found in appsettings.json.
date: "2026-11-02T15:47:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified against CVE-2026-120442 advisory.
cpes:
  - cpe:2.3:a:ape-volo:ape-volo-admin:*:*:*:*:*:*:*:*
vendors:
  - ape-volo
products:
  - ape-volo-admin (< 3.6.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552.001
    technique_name: Credentials In Files
    evidence: An unauthenticated attacker can leverage this key to perform offline token forging by crafting JWTs with a 'jti' claim corresponding to an administrator ID.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1187
    technique_name: Forced Authentication
    evidence: An unauthenticated attacker can leverage this key to perform offline token forging by crafting JWTs with a 'jti' claim corresponding to an administrator ID, resulting in full administrative access.
    confidence_band: high
cves:
  - id: CVE-2026-120442
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120442
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade ape-volo-admin to version 3.6.1 or later.
      owner: IT Operations
      due: 24h
      evidence: Source specifies this version remediates the vulnerability.
  hunt_leads:
    - lead: Search for unauthorized administrative activity or unusual API call patterns following the use of spoofed JWTs.
      technique_id: T1552.001
      data_needed:
        - API access logs
        - Application audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The flaw allows full API control; hunt for anomalies in user management and permission changes.
  mitigation_plan:
    - priority: immediate
      action: Rotate JWT signing key in appsettings.json.
      owner: IT Operations
      addresses: CVE-2026-120442
      evidence: Hardcoded key in appsettings.json is the root cause.
---

The ape-volo-admin application prior to version 3.6.1 is vulnerable to an authentication bypass. The software uses a hardcoded JWT signing key stored in the 'appsettings.json' configuration file. An attacker with access to this file, or knowledge of the key, can perform offline token forging. By signing a JWT with the 'jti' claim set to a known administrator ID, an attacker can gain unauthorized administrative access to the API, including control over users, roles, permissions, and data.

## Impact

Successful exploitation allows unauthenticated attackers to gain full administrative privileges over the ape-volo-admin instance, enabling complete control over user management, data access, and system configuration.

## Recommendation

- Upgrade to ape-volo-admin version 3.6.1 or later immediately.
- Review and rotate the JWT signing key defined in 'appsettings.json' if it is suspected that the configuration file has been exposed or accessed by unauthorized parties.
- Audit API access logs for anomalous administrative actions or token usage patterns originating from unexpected sources.
