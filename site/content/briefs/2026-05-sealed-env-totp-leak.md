---
title: sealed-env Enterprise Mode TOTP Secret Leak in Unseal Tokens (CVE-2026-45091)
slug: 2026-05-sealed-env-totp-leak
description: sealed-env versions 0.1.0-alpha.1 through 0.1.0-alpha.3 embedded the operator's literal TOTP secret in the JWS payload of every minted unseal token, allowing an attacker with a leaked token and the master key to mint new unseal tokens indefinitely.
date: "2026-05-12T15:09:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - credential-access
  - cve-2026-45091
  - sealed-env
products:
  - sealed-env (< 0.1.0-alpha.4)
  - sealed-env-core (< 0.1.0-alpha.4)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-45091
    cvss: 9.1
references:
  - https://github.com/advisories/GHSA-x3r2-fj3r-g5mv
  - CVE-2026-45091
rules:
  - title: Detect sealed-env Unseal Token with Base64 Encoded TOTP Secret
    description: Detects sealed-env unseal tokens potentially containing a base64 encoded TOTP secret in enterprise mode by identifying tokens with a JWS structure.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - file_event
      - linux
  - title: Detect Sealed-env Unseal Token File Creation
    description: Detects the creation of a .token file which may contain the unseal token.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Versions 0.1.0-alpha.1 through 0.1.0-alpha.3 of sealed-env, when running in enterprise mode, improperly handled TOTP secrets. The application embedded the operator's plaintext TOTP secret within the JWS payload of each minted unseal token. Since JWS payloads are base64-encoded JSON and not encrypted, any entity that observed a minted token could extract the TOTP secret. This exposure could occur through various channels, including CI build logs, container environment dumps, `kubectl describe pod` outputs, or log aggregation systems. The issue was reported by an external reviewer after decoding the payload of a real minted token and confirming it matched the operator's `.env.local` TOTP secret. Version 0.1.0-alpha.4 patches this vulnerability (CVE-2026-45091) by replacing the embedded secret with a salt-bound HMAC derivative (`enterprise_epoch = HMAC(totpSecret, salt || "epoch-v1")`). The change is incompatible, requiring re-sealing and TOTP secret rotation.

## Attack Chain

1. Attacker gains unauthorized access to the master key, possibly through a leaked CI secret or other compromise.
2. The attacker intercepts or obtains a single, previously minted unseal token. This token could be found in CI build logs, container environment variables, or other exposed locations.
3. The attacker decodes the base64-encoded JWS payload of the intercepted unseal token.
4. The attacker extracts the plaintext TOTP secret from the decoded JWS payload.
5. The attacker, possessing both the master key and the TOTP secret, can now generate valid unseal tokens.
6. The attacker uses the generated unseal tokens to unseal the environment for unauthorized deployments.
7. The attacker maintains persistent, unauthorized access to the sealed environment indefinitely.
8. The attacker achieves their objective, such as data exfiltration or code execution.

## Impact

The vulnerability allows attackers to bypass the intended two-factor unsealing mechanism of sealed-env. An attacker with the master key and a single leaked unseal token can generate new, valid unseal tokens indefinitely. This compromises the security of any environment protected by sealed-env, allowing for unauthorized deployments and potentially leading to data breaches, service disruption, or other malicious activities. Successful exploitation allows unauthorized persistent access to sensitive applications and data protected by sealed-env.

## Recommendation

*   Upgrade to sealed-env version 0.1.0-alpha.4 or later to address CVE-2026-45091.
*   Rotate the TOTP secret after upgrading to version 0.1.0-alpha.4, as the old secret may have been compromised.
*   Reseal all files sealed by affected versions (0.1.0-alpha.1 through 0.1.0-alpha.3) due to the incompatible wire format change detailed in the CHANGELOG.md.
*   Implement robust logging and monitoring to detect unauthorized access attempts or unusual unsealing activities related to the leaked TOTP.
*   Examine historical logs for any exposed unseal tokens in CI build logs, container environment dumps, `kubectl describe pod` outputs, or log aggregation systems.
