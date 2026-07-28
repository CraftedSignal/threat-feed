---
title: Path Traversal Vulnerability in openhole-server (CVE-2026-54650)
slug: 2026-07-openhole-server-path-traversal
description: An unauthenticated path traversal vulnerability (CVE-2026-54650) in openhole-server and openhole CLI versions 0.1.1 and earlier allows remote attackers to read arbitrary files outside the web root on tunneled local services by exploiting URL-decoded percent-encoded dot-segments and slashes, enabling arbitrary file disclosure and potential bypass of access controls.
date: "2026-07-28T22:24:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - path-traversal
  - webserver
vendors:
  - bablilayoub
products:
  - openhole-server (<= 0.1.1)
  - openhole CLI (<= 0.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: openhole-server vulnerable to path traversal via URL-decoded request path... An unauthenticated remote attacker could read files outside the published web root on tunneled local services.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: 'An unauthenticated remote attacker could read files outside the published web root on tunneled local services... Example: /%2e%2e/%2e%2e/etc/passwd → sensitive files'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-fh2f-xfxc-q9cc
rules:
  - title: Detect CVE-2026-54650 Exploitation Attempt in openhole-server
    description: Detects CVE-2026-54650 exploitation - HTTP requests to openhole-server containing URL-encoded path traversal sequences (%2e%2e or %2f) in the URI stem or query parameters.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1005
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A high-severity path traversal vulnerability, tracked as CVE-2026-54650, affects `openhole-server` and the `openhole CLI` in versions 0.1.1 and earlier. Discovered by GHSA, this flaw allows an unauthenticated remote attacker to access arbitrary files outside the intended web root on local services exposed through the `openhole` tunnel. The vulnerability stems from the server incorrectly forwarding the URL-decoded request path (`r.URL.Path`) to tunnel clients instead of preserving the original, percent-encoded request-target. This leads to percent-encoded dot-segments (`%2e%2e/` for `../`) and separators (`%2f` for `/`) being decoded and interpreted literally by the backend, bypassing Go's `ServeMux` protections against literal path traversals. This could enable attackers to read sensitive configuration files, system files like `/etc/passwd`, and potentially bypass existing path-based access controls.

## Attack Chain

1. An unauthenticated remote attacker crafts a malicious HTTP request targeting an `openhole-server` instance.
2. The request path includes specifically engineered URL-encoded directory traversal sequences, such as `/%2e%2e/` (for `../`) and potentially `%2f` (for `/`).
3. The `openhole-server` receives this request and, due to the vulnerability, URL-decodes the `r.URL.Path` parameter.
4. The percent-encoded traversal sequences are transformed into their literal forms (e.g., `%2e%2e` becomes `..` and `%2f` becomes `/`).
5. The server then forwards this URL-decoded path to the tunneled backend service, effectively bypassing Go's `ServeMux` protection that typically rejects literal `../` sequences.
6. The backend service processes the path, interpreting the literal `../` sequences as directory traversals, allowing access to files outside its intended web root or application directory.
7. The attacker gains unauthorized access to and reads sensitive files (e.g., `/etc/passwd`, application configuration files) from the victim's system, which are then returned in the HTTP response.

## Impact

Successful exploitation of CVE-2026-54650 can lead to severe consequences for organizations utilizing vulnerable versions of `openhole-server`. An unauthenticated remote attacker can read arbitrary files from the underlying system that hosts the tunneled service, beyond the intended web or application root. This can expose sensitive information such as user credentials, system configuration, source code, and other proprietary data. The vulnerability also allows for the bypass of path-based access controls, potentially granting access to restricted areas or functionalities. While specific victim counts or targeted sectors are not detailed, any organization using affected `openhole-server` instances is at risk of significant data breaches and unauthorized system access.

## Recommendation

* Immediately upgrade `openhole-server` and `openhole CLI` to version `v0.1.2` or later to remediate CVE-2026-54650.
* Deploy the Sigma rule "Detect CVE-2026-54650 Exploitation Attempt in openhole-server" to your SIEM to identify HTTP requests containing suspicious URL-encoded path traversal sequences.
* Enable comprehensive webserver logging to capture full HTTP request paths and query parameters for detection and forensic analysis.
