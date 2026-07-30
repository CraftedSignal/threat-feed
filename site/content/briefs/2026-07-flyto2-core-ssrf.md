---
title: Flyto2 Core SSRF via Insecure Redirect Handling
slug: 2026-07-flyto2-core-ssrf
description: Flyto2 Core HTTP modules perform insufficient SSRF revalidation on HTTP redirects, allowing attackers to reach internal resources and cloud metadata services.
date: "2026-07-30T15:29:20Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Flyto2
products:
  - Flyto2 Core (2.26.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker hosts a public URL that 302-redirects to an internal address; the guard passes on the public host and aiohttp transparently follows the redirect into internal space, returning the internal body.
    confidence_band: high
cves:
  - id: CVE-2026-67424
    cvss: 8.5
    epss: 0.00236
references:
  - https://github.com/advisories/GHSA-c9hr-64h3-gxpc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67424
---

Flyto2 Core versions 2.26.6 and earlier contain a critical Server-Side Request Forgery (SSRF) vulnerability due to improper handling of HTTP redirects. The application's HTTP modules, including `http.get`, `http.request`, and `http.batch`, perform initial URL validation against an allowlist before execution. However, these modules rely on the default behavior of the aiohttp library, which automatically follows HTTP redirects without performing per-hop revalidation.

An attacker can bypass security controls by providing a malicious public-facing URL that returns a 302 redirect to an internal IP address or sensitive cloud metadata endpoint (e.g., `169.254.169.254`). Because the application does not inspect the `Location` header or re-verify the redirect target against the internal allowlist, the aiohttp client transparently follows the request to the restricted resource. This results in the potential exfiltration of sensitive internal configuration, metadata, or other network-accessible data. This vulnerability affects all deployments using standard module configurations where redirects are permitted by the underlying client.

## Attack Chain

1. Attacker identifies a target application utilizing Flyto2 Core for external HTTP requests.
2. Attacker hosts a public, innocuous-looking URL (e.g., `http://attacker.tld/r`) configured to return an HTTP 302 redirect.
3. Attacker triggers a request to the target application, passing the public URL to a vulnerable function like `http.get`.
4. The target application's `validate_url_with_env_config` function evaluates the initial URL (`attacker.tld`), which is deemed safe, and passes validation.
5. The application invokes `session.get(url)` via aiohttp, which by default is set to `allow_redirects=True`.
6. The aiohttp client receives the 302 redirect and automatically initiates a new request to the internal destination (e.g., `http://169.254.169.254/...`).
7. No per-hop validation occurs, allowing the request to succeed against the internal host.
8. The sensitive data returned from the internal host is relayed back to the attacker as the final response body.

## Impact

Successful exploitation allows for unauthorized access to internal services and cloud metadata endpoints that are otherwise unreachable from the public internet. This can lead to the exposure of credentials, environment variables, or other sensitive infrastructure details. The vulnerability affects all users of Flyto2 Core versions 2.26.6 and earlier.

## Recommendation

1. Upgrade Flyto2 Core to the latest patched version once available to address CVE-2026-67424.
2. If an immediate upgrade is not feasible, implement manual revalidation of the `Location` header in the HTTP module codebase by disabling `allow_redirects` and explicitly checking redirect targets against the allowlist.
3. Deploy egress filtering on servers running Flyto2 Core to restrict access to internal IP ranges (e.g., 169.254.0.0/16, 127.0.0.0/8) from the application process.
