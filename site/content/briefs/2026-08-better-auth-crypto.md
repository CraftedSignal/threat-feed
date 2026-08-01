---
title: Insecure Cryptographic Defaults in better-auth OIDC and MCP Plugins
slug: 2026-08-better-auth-crypto
description: better-auth versions before 1.6.11 enable insecure OIDC and PKCE configurations by default, allowing attackers to bypass authentication through algorithm negotiation and authorization code interception.
date: "2026-08-01T13:54:54Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - better-auth (< 1.6.11)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers can exploit algorithm negotiation to accept unsigned tokens or intercept authorization codes
    confidence_band: high
cves:
  - id: CVE-2026-67336
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67336
  - https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4
  - https://www.vulncheck.com/advisories/better-auth-before-insecure-cryptographic-defaults-via-oidcprovider
---

better-auth versions prior to 1.6.11 contain insecure cryptographic defaults within the `oidcProvider` and `mcp` plugins. The vulnerability stems from the library advertising the `none` algorithm for OpenID Connect (OIDC) tokens and defaulting to `plain` Proof Key for Code Exchange (PKCE) rather than the industry-standard `S256` method. 

This misconfiguration enables remote attackers to manipulate the algorithm negotiation process, forcing the application to accept unsigned tokens. Furthermore, the reliance on `plain` PKCE allows adversaries to intercept authorization codes, leading to potential full authorization bypass. The impact is significant for applications relying on better-auth for secure authentication and authorization flows, as it effectively negates the security guarantees provided by OIDC and PKCE. Defenders should immediately audit environments for better-auth versions below 1.6.11 and prioritize upgrades.

## Impact

Successful exploitation allows for full authentication bypass and unauthorized access to sensitive application data. By manipulating the OIDC token exchange, attackers can impersonate legitimate users and escalate privileges within systems integrated with the vulnerable better-auth plugins. This flaw exposes authentication services to high-risk interception and token forgery attacks.

## Recommendation

- Upgrade the `better-auth` library to version 1.6.11 or higher across all development and production environments.
- Audit all `oidcProvider` configurations to ensure that the `none` algorithm is explicitly disabled and that `code_challenge_method` is set strictly to `S256`.
- Conduct a security review of authentication logs for anomalous token validation patterns or usage of `plain` PKCE challenges in the OAuth flow.
- Monitor dependencies using software composition analysis (SCA) tools to ensure that vulnerable versions of better-auth are identified and patched immediately.
