---
title: Path Traversal and Query Injection in hashi-vault-js
slug: 2026-07-hashi-vault-js-traversal
description: The hashi-vault-js library is vulnerable to path traversal and query injection due to insufficient URI encoding, potentially allowing attackers to redirect administrative Vault requests if untrusted input is passed to the library.
date: "2026-07-31T19:29:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - injection
  - path-traversal
  - npm
  - cve-2026-55100
products:
  - hashi-vault-js (0.5.1)
cves:
  - id: CVE-2026-55100
references:
  - https://github.com/advisories/GHSA-g956-2f74-rmv7
  - CVE-2026-55100
---

The npm package `hashi-vault-js` (versions 0.5.1 and earlier) contains critical flaws in how it constructs HTTP requests for the HashiCorp Vault API. The library fails to perform URI encoding on identifier parameters, such as secret names, versions, or group names, before concatenating them into request strings. 

This implementation error allows two distinct exploitation vectors: Path Traversal and Query Parameter Injection. An attacker capable of influencing the input provided to these methods can force the client to target arbitrary Vault API endpoints, including sensitive administrative paths prefixed with `/sys/`. If the application uses a token with high-privileged permissions, an attacker may be able to perform unauthorized administrative actions, such as unsealing the vault or modifying system configurations, depending on the scope of the token assigned to the vulnerable application.

## Attack Chain

1. The application consumes user-supplied input (e.g., from a URL parameter, form field, or API request).
2. The application passes this untrusted input into a `hashi-vault-js` method (e.g., secret retrieval or versioning).
3. The `hashi-vault-js` library concatenates the raw input directly into the destination URL string without sanitization.
4. The attacker provides a payload such as `../../sys/seal` to trigger a path traversal or `1&list=true` for query injection.
5. The library's HTTP client normalizes the resulting malicious URL path or query string.
6. The client transmits the request to an unintended administrative Vault API endpoint.
7. The Vault server processes the request within the context of the application's authenticated session token.
8. The attacker achieves unauthorized read/write or configuration operations depending on the token's configured policy.

## Impact

Successful exploitation allows unauthorized interaction with the Vault server. By redirecting requests to administrative endpoints, an attacker can bypass intended logic, potentially leading to unauthorized data exposure, configuration modification, or service disruption. The impact is primarily constrained by the policy permissions associated with the service account token used by the vulnerable application.

## Recommendation

1. Update `hashi-vault-js` to a patched version that implements `encodeURIComponent` for all path segments and query parameters.
2. Audit all application code that utilizes `hashi-vault-js` to ensure that any variable input passed to the library is validated against a strict allowlist.
3. As an immediate temporary workaround, manually sanitize and encode all user-supplied variables using `encodeURIComponent()` before passing them to the library's methods.
4. Ensure that the Vault tokens assigned to applications follow the principle of least privilege, minimizing the damage potential if the application is compromised via these injection vectors.
