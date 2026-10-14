---
title: Authentication Bypass in vlife via Hardcoded JWT Signing Key
slug: 2026-10-vlife-auth-bypass
description: The vlife application through version 2.0.1 contains a hardcoded HS256 JWT signing key in TokenUtil, allowing unauthenticated attackers to forge tokens and gain administrative privileges.
date: "2026-10-14T16:32:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vlife:vlife:*:*:*:*:*:*:*:*
vendors:
  - vlife
products:
  - vlife (<= 2.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: vlife through 2.0.1 contains an authentication bypass vulnerability that allows unauthenticated attackers to forge JWTs
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1185
    technique_name: Browser Session Hijacking
    evidence: Attackers can sign a token with superUser=true and arbitrary groupIds claims to gain super administrator access
    confidence_band: high
cves:
  - id: CVE-2026-110612
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110612
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade vlife to version > 2.0.1
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-110612
  mitigation_plan:
    - priority: immediate
      action: Upgrade vlife to version > 2.0.1
      owner: IT Operations
      addresses: CVE-2026-110612
      evidence: NVD vulnerability disclosure
---

vlife versions up to and including 2.0.1 contain a critical authentication bypass vulnerability (CVE-2026-110612). The vulnerability stems from the TokenUtil component, which utilizes a hardcoded HS256 signing key for JSON Web Token (JWT) generation. Because the secret key is embedded within the application source code or compiled binary, an unauthenticated attacker who gains access to the key can programmatically forge tokens. By crafting a JWT with the 'superUser' claim set to true and arbitrary 'groupIds', an attacker can impersonate any user, including high-privilege system administrators, to gain full control over the affected vlife instance. This flaw enables complete unauthorized access to all application URLs and functionalities.

## Impact

Successful exploitation results in full administrative takeover of the vlife platform. This bypass allows an unauthenticated actor to perform any action available to a super administrator, including data exfiltration, configuration modification, and account management. The severity is reflected in a CVSS v3.1 base score of 9.8.

## Recommendation

* Immediately upgrade vlife to a version beyond 2.0.1 that removes the hardcoded signing key.
* Audit access logs for any anomalous JWTs or authentication claims that appear outside of the established identity provider flow.
* Implement strict network perimeter controls to restrict access to administrative endpoints if patching cannot be performed immediately.
