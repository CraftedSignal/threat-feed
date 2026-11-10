---
brief_id: brief-2026-11-10-esm-sh-path-traversal
event_id: brief-2026-11-10-esm-sh-path-traversal
revision: 1
activity_at: "2026-11-10T04:16:54Z"
title: 'esm.sh: web.NewHandler arbitrary file read via encoded dot-segment path traversal (CVE-2026-102657)'
slug: 2026-11-esm-sh-path-traversal
description: An unauthenticated path traversal vulnerability in esm.sh/web allows remote attackers to read arbitrary files by sending requests with URL-encoded dot-segments.
date: "2026-11-10T04:16:54Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:esm_sh:esm_sh_web:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - cve-2026-102657
  - arbitrary-file-read
vendors:
  - esm.sh
products:
  - esm.sh/web (< 0.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The documented web.NewHandler static file server can read files outside Config.AppDir when the request path contains URL-encoded dot-segments.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: An unauthenticated remote attacker can read files that are outside the configured web application directory.
    confidence_band: high
cves:
  - id: CVE-2026-102657
    cvss: 7.5
    epss: 0.00716
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-g3c2-rjq2-c763
rules:
  - title: Detect CVE-2026-102657 Exploitation - Encoded Dot-Segment Path Traversal
    description: Detects attempts to exploit CVE-2026-102657 by searching for URL-encoded dot-segments in HTTP request URIs.
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
    - action: Patch esm.sh/web to version 0.2.0 or later
      owner: IT Operations
      due: 24h
      evidence: Vulnerable version is < 0.2.0
  hunt_leads:
    - lead: Inspect web server access logs for anomalous encoded path sequences
      technique_id: T1190
      data_needed:
        - cs-uri-query
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Encoded dot-segments are used to bypass path normalization
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to block %2e%2e in URI
      owner: IT Operations
      addresses: CVE-2026-102657
      evidence: Source advises that encoded dot-segments bypass ServeMux
---

The `web.NewHandler` component in `esm.sh/web` (versions < 0.2.0) contains a path traversal vulnerability. When a request path contains URL-encoded dot-segments (e.g., `%2e%2e`), Go's `ServeMux` fails to redirect the request, and the handler proceeds to join the decoded path with `AppDir` without performing a containment check. This allows unauthenticated attackers to read files located outside the intended application directory, restricted only by the filesystem permissions of the server process.

## Attack Chain

1. Attacker crafts an HTTP GET request containing URL-encoded traversal segments (e.g., `/%2e%2e/%2e%2e/secret.txt`).
2. The network-facing `http.ServeMux` decodes the request path.
3. Because the segments are URL-encoded, `ServeMux` does not block or redirect the request.
4. The request is passed to `web.NewHandler`.
5. `web.NewHandler` joins the `Config.AppDir` path with the decoded `r.URL.Path`.
6. The application performs `os.Lstat` and `os.Open` on the resulting path, which resolves to a location outside the application directory.
7. The server reads the file content and copies it into the HTTP response body, disclosing sensitive data to the attacker.

## Impact

Successful exploitation allows unauthenticated remote attackers to read arbitrary files on the filesystem accessible to the application process. This may include configuration files, environment variables, source code, or private keys, depending on the server configuration and file permissions.

## Recommendation

1. Upgrade `esm.sh/web` to version 0.2.0 or later immediately.
2. For environments where upgrading is delayed, apply input validation at the web server or proxy level to block request paths containing `%2e` or `..` segments.
3. Ensure the web application runs with the principle of least privilege, restricting the filesystem access of the process to the absolute minimum required by `AppDir`.
