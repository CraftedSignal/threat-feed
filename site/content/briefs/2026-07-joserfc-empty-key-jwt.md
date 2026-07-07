---
title: 'joserfc: HS256/HS384/HS512 verify accepts empty/nil HMAC key (CVE-2026-49852)'
slug: 2026-07-joserfc-empty-key-jwt
description: A critical vulnerability, CVE-2026-49852, exists in the Python `joserfc` library (versions `<= 1.6.7`) where HMAC-signed JSON Web Tokens can be forged, leading to complete authentication bypass, if the application is configured to verify tokens with an empty or `None` HMAC key.
date: "2026-07-03T11:46:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - jwt
  - python
  - vulnerability
  - cve
vendors:
  - Authlib
products:
  - joserfc <= 1.6.7
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A critical vulnerability exists in the joserfc library... enables complete authentication bypass... leads to unauthorized access.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-gg9x-qcx2-xmrh
  - https://github.com/authlib/joserfc-ghsa-gg9x-qcx2-xmrh/pull/1
---

A significant vulnerability, CVE-2026-49852, has been identified in the `joserfc` Python library (versions `<= 1.6.7`), allowing for complete authentication bypass. This flaw, a cross-language sibling of CVE-2026-45363 affecting `ruby-jwt`, enables an unauthenticated attacker to forge valid HMAC-signed JSON Web Tokens (HS256, HS384, HS512) without any secret knowledge. The vulnerability arises when an application using `joserfc.jwt.decode` inadvertently supplies an empty string or `None` as the HMAC verification key. This misconfiguration commonly occurs when keys are sourced from unset environment variables, missing database entries, or fallbacks that return empty values. Although `joserfc` issues a `SecurityWarning` for short keys, it does not reject zero-length keys, leading to successful verification of attacker-crafted tokens and unauthorized access.

## Attack Chain

1.  **Application Misconfiguration**: A Python application using `joserfc` is configured such that its JWT HMAC verification key resolves to an empty string (`""`) or `None` (e.g., `os.environ.get("JWT_SECRET", "")` if `JWT_SECRET` is unset).
2.  **Attacker Crafts Claims**: The attacker creates a JSON payload with arbitrary claims (e.g., `{"sub": "attacker", "admin": True}`).
3.  **Attacker Prepares JWT**: The attacker constructs the JWT header (`{"alg": "HS256", "typ": "JWT"}`) and the crafted payload, then Base64Url-encodes them to form the `signing_input`.
4.  **Attacker Signs with Empty Key**: The attacker generates an HMAC signature by hashing the `signing_input` using an empty key (`hmac.new(b"", signing_input, hashlib.sha256).digest()`).
5.  **Attacker Submits Forged Token**: The attacker concatenates the header, payload, and the empty-key signature into a full JWT and submits it to the vulnerable application.
6.  **Application Attempts Verification**: The application receives the forged JWT and attempts to verify it using `joserfc.jwt.decode`, which retrieves the misconfigured empty key.
7.  **Vulnerable Verification**: `joserfc`'s `HMACAlgorithm.verify` uses the empty key to re-compute the HMAC digest, which matches the attacker's empty-key signature.
8.  **Unauthorized Access**: The `joserfc` library successfully decodes the forged token, allowing the application to grant the attacker unauthorized access with the arbitrary claims, such as elevated administrative privileges.

## Impact

The vulnerability in `joserfc` allows for a complete authentication bypass, enabling unauthenticated attackers to forge arbitrary claims, including user roles, scopes, and expiration times. This directly leads to unauthorized access to protected resources and potential privilege escalation on any service utilizing the `joserfc` library with a misconfigured empty HMAC key. While the precondition for exploitation requires an operator misconfiguration (e.g., an unset environment variable), the silence of the misconfiguration (only a `SecurityWarning` is emitted, not an error) makes it a critical threat. The vulnerability has a CVSS 3.1 score of 7.4 (High), indicating significant confidentiality and integrity impact due to the authentication bypass.

## Recommendation

*   **Patch CVE-2026-49852**: Urgently update the `joserfc` library to a patched version once available. Monitor the `Authlib` GitHub repository and PyPI for the release.
*   **Review Secret Management**: Implement strict controls to ensure that JWT secrets are never empty strings or `None` when retrieved from environment variables, configuration files, or key finders. Ensure that `OctKey.import_key` always receives a non-empty, sufficiently long secret.
*   **Implement Key Length Validation**: Manually implement a check for key length (e.g., `if not key or len(key) < 14: raise ValueError("HMAC key invalid")`) before passing it to `joserfc.jwt.decode` if an immediate upgrade is not possible.
*   **Inventory `joserfc` Usage**: Scan your codebase for all instances of `joserfc.jwt.decode` and the versions of the `joserfc` package (`pip/joserfc`) deployed in your environment, particularly those running versions `<= 1.6.7`.
