---
title: Path Traversal in FileBrowser Subtitle Handler
slug: 2026-08-filebrowser-traversal
description: An unauthenticated-accessible path traversal vulnerability in FileBrowser's subtitle handler allows authenticated users to read arbitrary files from the host filesystem, leading to potential credential theft and privilege escalation.
date: "2026-08-01T01:47:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - cve-2026-54910
  - filebrowser
vendors:
  - FileBrowser
products:
  - filebrowser/backend
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The subtitlesHandler endpoint accepts two user-controlled query parameters, path and name, both of which are used in filesystem operations without sanitization.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Any authenticated user can exploit either vector to read any text file readable by the server process, including /etc/passwd, SSH keys, database credentials, and JWT signing keys.
    confidence_band: high
cves:
  - id: CVE-2026-54910
    cvss: 7.7
    epss: 0.00307
rules:
  - title: Detect CVE-2026-54910 Exploitation - Path Traversal in FileBrowser
    description: Detects exploitation attempts against the FileBrowser subtitle handler by monitoring for directory traversal sequences in GET requests to the /api/media/subtitles endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1210
    data_sources:
      - webserver
rules_count: 1
---

FileBrowser is vulnerable to a path traversal issue in the `subtitlesHandler` endpoint (GET /api/media/subtitles) due to improper input sanitization of the `path` and `name` query parameters. This vulnerability, identified as CVE-2026-54910, affects the `filebrowser` backend versions prior to `0.0.0-20260608182036-f3f4bbe80cb5`. The flaw allows any authenticated user, regardless of their assigned permissions, to bypass storage scope restrictions and read arbitrary text files on the host filesystem that the application process has access to.

The vulnerability manifests through two distinct vectors. First, the `path` parameter is passed directly to filesystem operations without calling `SanitizeUserPath()`, enabling full directory traversal. Second, the `name` parameter is concatenated via `filepath.Join` without stripping directory components, also allowing traversal if a valid anchor file is present. An attacker can use these vectors to exfiltrate sensitive files such as `/etc/passwd`, SSH private keys, database credentials, and application JWT signing keys. The only functional constraint is that the target file must be valid UTF-8 and under 50MB in size.

## Attack Chain

1. Attacker authenticates to the FileBrowser instance using valid user credentials.
2. Attacker crafts a malicious HTTP GET request to the `/api/media/subtitles` endpoint.
3. Attacker injects path traversal sequences (e.g., `../../etc/passwd`) into the `path` query parameter.
4. The application logic executes `idx.GetRealPath()` using the unsanitized `path` input, resolving the directory outside of the intended storage scope.
5. The application calls `utils.GetSubtitleSidecarContent()` with the traversed path.
6. The `os.ReadFile()` function within the utility module opens the target file on the host filesystem.
7. The application returns the contents of the file in the HTTP response body to the attacker.
8. Attacker parses the response to exfiltrate sensitive configuration files, secrets, or system credentials.

## Impact

The impact of this vulnerability is significant, as it enables arbitrary file read on the host machine. Successful exploitation grants attackers access to system-level files like `/etc/passwd` and application-level secrets such as JWT signing keys, which facilitate administrative token forgery and full system compromise. The attack requires only basic authentication, making it accessible to any compromised low-privileged user account within the environment.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

- Deploy the provided Sigma rule to detect suspicious HTTP requests targeting the subtitle endpoint with traversal sequences.
- Upgrade the `filebrowser` backend to the latest version, as specified in the vendor advisory for CVE-2026-54910.
- Implement strict ingress filtering at the Web Application Firewall (WAF) layer to block any HTTP requests containing directory traversal sequences (e.g., `../`, `..%2f`) directed at the `/api/media/subtitles` path.
- Audit logs for the `/api/media/subtitles` endpoint to identify successful requests from non-administrative users that result in unusual file content retrieval patterns.
