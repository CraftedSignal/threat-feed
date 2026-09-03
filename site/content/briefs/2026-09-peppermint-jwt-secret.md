---
title: Hardcoded JWT Signing Secret in Peppermint
slug: 2026-09-peppermint-jwt-secret
description: Peppermint versions through 0.5.5 contain a hardcoded JWT signing secret in docker-compose.yml, allowing unauthenticated attackers to forge arbitrary session tokens.
date: "2026-09-03T19:22:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:peppermint:peppermint:*:*:*:*:*:*:*:*
vendors:
  - Peppermint
products:
  - Peppermint (<= 0.5.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Peppermint through 0.5.5 contains a hardcoded JWT signing secret in docker-compose.yml that allows unauthenticated attackers to forge session tokens for any account.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials in Files'
    evidence: Peppermint through 0.5.5 contains a hardcoded JWT signing secret in docker-compose.yml.
    confidence_band: high
cves:
  - id: CVE-2026-85391
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85391
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Rotate the JWT signing secret and update docker-compose.yml to use environment-injected secrets.
      owner: IT Operations
      due: 24h
      evidence: Hardcoded JWT secret allows arbitrary session token creation.
  mitigation_plan:
    - priority: immediate
      action: Remove the hardcoded secret from the environment and rotate all existing session tokens.
      owner: IT Operations
      addresses: CVE-2026-85391
      evidence: Hardcoded secret facilitates unauthenticated access.
---

Peppermint versions up to and including 0.5.5 suffer from a critical security vulnerability involving a hardcoded JWT signing secret located in the project's docker-compose.yml file. By design, this secret is intended to sign session tokens for authenticating users. Because the secret is public and hardcoded within the repository, any unauthenticated attacker can retrieve it and use it to sign and forge valid JWT session tokens for any account within the target instance. This flaw allows unauthorized access to protected endpoints and complete account takeover, effectively bypassing authentication mechanisms. This impact is significant as it provides high-privileged access without requiring credentials. Organizations deploying Peppermint 0.5.5 or earlier should prioritize rotating this secret and upgrading to a remediated version once available.

## Impact

The vulnerability allows for complete authentication bypass and account takeover on any Peppermint instance using the default docker-compose configuration. An attacker can impersonate any user, including administrative accounts, to gain unauthorized access to sensitive application data and functions.

## Recommendation

Prioritize the following actions to secure Peppermint environments:
- Audit the docker-compose.yml file for the presence of the hardcoded secret and revoke it immediately.
- Implement environment variable management to inject secrets at runtime rather than hardcoding them in configuration files.
- Monitor logs for unusual authentication patterns or tokens signed with the default secret if it cannot be immediately rotated.
- Upgrade Peppermint to a patched version once released by the maintainers.
