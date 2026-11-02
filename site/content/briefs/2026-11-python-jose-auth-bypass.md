---
brief_id: brief-2026-11-02-python-jose-auth-bypass
event_id: brief-2026-11-02-python-jose-auth-bypass
revision: 1
activity_at: "2026-11-02T15:51:14Z"
title: 'python-jose: Authentication bypass via JWT forgery (CVE-2026-120459)'
slug: 2026-11-python-jose-auth-bypass
description: The python-jose library through version 3.5.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to forge JWTs by exploiting the librarys acceptance of zero-length HMAC secrets.
date: "2026-11-02T15:51:14Z"
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
  validation_status: Requires application-level audit of python-jose dependency versions
cpes:
  - cpe:2.3:a:python-jose_project:python-jose:*:*:*:*:*:*:*:*
products:
  - python-jose (<= 3.5.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The python-jose library through version 3.5.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to forge JWTs.
    confidence_band: high
cves:
  - id: CVE-2026-120459
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120459
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Identify applications using python-jose versions <= 3.5.0 in the dependency inventory
      owner: Application Security
      due: 48h
      evidence: Vulnerability affects python-jose 3.5.0 and earlier
  hunt_leads:
    - lead: Identify applications performing JWT validation using python-jose that log empty or unexpected HMAC secret configurations
      technique_id: T1550
      data_needed:
        - Application audit logs
        - Source code analysis
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Applications where verification key resolves to empty are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade python-jose to a version where CVE-2026-120459 is patched
      owner: IT Operations
      addresses: CVE-2026-120459
      evidence: Library vulnerability mitigation
---

CVE-2026-120459 describes an authentication bypass vulnerability in python-jose versions 3.5.0 and earlier. The flaw exists in the HMACKey and CryptographyHMACKey implementations, which incorrectly accept zero-length HMAC secrets during JWT verification. If an application relies on these methods to verify HS256, HS384, or HS512 tokens and the verification key resolves to an empty value (or an octet JWK with an empty 'k' parameter), an attacker can successfully forge tokens containing arbitrary claims that are accepted by jwt.decode.

## Impact

Successful exploitation allows an unauthenticated attacker to bypass authentication mechanisms and impersonate arbitrary users by forging validly signed JWTs.

## Recommendation

Update to the latest version of python-jose where the fix is implemented. Until an upgrade is possible, audit application code to ensure that HMAC verification keys are strictly validated for non-zero length before being passed to the library.
