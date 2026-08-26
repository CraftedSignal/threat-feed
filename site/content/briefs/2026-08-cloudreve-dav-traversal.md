---
title: Cloudreve WebDAV Path Traversal Vulnerability
slug: 2026-08-cloudreve-dav-traversal
description: A path traversal vulnerability in Cloudreve's WebDAV handler allows attackers with scoped credentials to escape their designated folder and perform unauthorized operations across the entire user namespace.
date: "2026-08-26T20:21:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - webdav
  - cve-2026-54563
vendors:
  - Cloudreve
products:
  - Cloudreve v3
  - Cloudreve v4
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Cloudreve WebDAV handler fails to validate that resolved paths stay within the authorized root, allowing traversal via encoded sequences.
    confidence_band: high
cves:
  - id: CVE-2026-54563
    cvss: 7.1
    epss: 0.00315
references:
  - https://github.com/advisories/GHSA-w5fv-7x5q-g8qp
rules:
  - title: Detect CVE-2026-54563 Exploitation - WebDAV Path Traversal
    description: Detects exploitation attempts against the Cloudreve WebDAV endpoint using URL-encoded traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Cloudreve to the versions specified in the advisory.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-54563 patch availability.
    - action: Deploy the provided Sigma detection rule to monitor for traversal patterns.
      owner: Detection Engineering
      due: 24h
      evidence: Source-confirmed exploitation vector via %2e%2e patterns.
  mitigation_plan:
    - priority: immediate
      action: WAF block for %2e%2e and %2f.. sequences on /dav.
      owner: IT Operations
      addresses: CVE-2026-54563
      evidence: Source proof-of-concept using encoded path traversal.
---

Cloudreve, a self-hosted file management and storage system, contains a critical path traversal vulnerability (CVE-2026-54563) in its WebDAV request handler. The issue stems from the `stripPrefix` function in `pkg/webdav/webdav.go`, which improperly sanitizes user-supplied paths before joining them to a defined account root. Because the application logic fails to validate that the final resolved path resides within the authorized account directory, attackers can leverage URL-encoded dot-dot sequences (e.g., `%2e%2e`) to traverse outside the intended folder boundaries.

This vulnerability specifically impacts the per-folder WebDAV-account isolation, which is intended to provide limited access to third-party sync clients. While the traversal does not permit cross-user file access or direct OS filesystem escalation, it allows an authenticated user to perform read, list, create, overwrite, move, or delete operations on any file within the parent user's entire namespace. The vulnerability affects both Cloudreve v3 and v4 branches.

## Attack Chain

1. Attacker obtains a scoped WebDAV credential for a specific folder within a Cloudreve instance.
2. Attacker crafts a WebDAV request (e.g., GET, PROPFIND, or PUT) targeting the `/dav` endpoint.
3. Attacker injects URL-encoded traversal sequences (`%2e%2e`) into the request path.
4. The WebDAV server receives the request and the `net/http` package decodes the traversal sequences into literal `..` segments.
5. The `stripPrefix` function in the Cloudreve handler joins the malicious path to the base URI without performing a containment check.
6. The `fs.URI.JoinRaw` and standard library `url.URL.JoinPath` functions resolve the `..` segments, escaping the intended account root.
7. The application executes the requested file operation (read, write, or list) against the escaped directory path within the victim's namespace.

## Impact

Successful exploitation allows unauthorized access to data outside the scope of the assigned WebDAV account. An attacker with read-only credentials can list and read any file within the entire user namespace, while a writable credential allows for the modification, deletion, or creation of arbitrary files in those directories. This compromises the isolation mechanism of scoped DAV accounts, effectively elevating an account's privileges to the full scope of the parent user's storage.

## Recommendation

- Upgrade to a patched version of Cloudreve (v4.0.0-20260606032813-26b6b1044b02 or later for v4; versions > 3.0.0-20250225100611-da4e44b77af4 for v3) to address CVE-2026-54563.
- Implement a Web Application Firewall (WAF) rule to block requests containing percent-encoded traversal sequences like `%2e%2e` or `%2f..%2f` targeting the `/dav` path.
- Audit WebDAV account permissions and rotate credentials for any accounts that may have been accessible to untrusted third parties.
- Enable detailed access logging on the Cloudreve webserver to monitor for suspicious `PROPFIND` or `PUT` requests containing traversal patterns.
