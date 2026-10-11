---
title: Authentication Bypass in BotSharp via Hard-Coded JWT Secret
slug: 2026-10-botsharp-auth-bypass
description: BotSharp versions 5.2.0 and earlier contain an authentication bypass vulnerability allowing unauthenticated attackers to forge administrative bearer tokens using a hard-coded JWT signing key.
date: "2026-10-11T16:02:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:botsharp:botsharp:*:*:*:*:*:*:*:*
vendors:
  - BotSharp
products:
  - BotSharp (<= 5.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: The flaw allows unauthenticated remote attackers to forge bearer tokens to impersonate any known user.
    confidence_band: high
cves:
  - id: CVE-2026-108860
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108860
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch or upgrade BotSharp to a secure version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-108860
    - action: Rotate all JWT signing keys in use within the BotSharp environment
      owner: IT Operations
      due: 24h
      evidence: Hard-coded key in appsettings.json identified as the source of vulnerability
  mitigation_plan:
    - priority: immediate
      action: Remove or rotate hard-coded secrets in appsettings.json
      owner: IT Operations
      addresses: CVE-2026-108860
      evidence: NVD vulnerability disclosure
---

BotSharp versions 5.2.0 and earlier are affected by a critical authentication bypass vulnerability (CVE-2026-108860). The flaw resides in the WebStarter component, where a hard-coded HMAC secret key is defined within the appsettings.json file for JWT signing. This static secret, combined with predictable issuer and audience fields, permits unauthenticated remote attackers to generate valid, signed JSON Web Tokens (JWTs). By successfully forging these tokens, an attacker can impersonate any user, including accounts with administrative privileges, to bypass authorization controls on API endpoints. This vulnerability significantly impacts the confidentiality and integrity of any organization deploying BotSharp, as it allows for full unauthorized access to protected API routes without requiring valid credentials.

## Impact

The vulnerability allows for complete compromise of the BotSharp application instance. Success grants attackers the ability to access, modify, or delete data through restricted API routes. There is no specific sector targeting mentioned, but any environment utilizing BotSharp as an agent orchestration framework is susceptible to full administrative takeover.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

- Update BotSharp deployments to a version that patches CVE-2026-108860 by removing hard-coded secrets from the configuration.
- Audit all BotSharp appsettings.json files for the existence of hard-coded JWT signing keys.
- Implement monitoring for anomalous or high-volume administrative actions originating from API requests, focusing on tokens with unexpected issuer or audience claims.
- Rotate all secrets and credentials used within the BotSharp environment, as the existing hard-coded key must be considered compromised.
