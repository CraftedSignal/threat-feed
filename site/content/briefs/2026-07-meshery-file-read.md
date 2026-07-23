---
title: CVE-2026-65919 Unauthenticated Arbitrary File Read in Meshery
slug: 2026-07-meshery-file-read
description: Meshery versions prior to 1.0.57 are vulnerable to an unauthenticated arbitrary file read due to a path traversal flaw in the /api/system/fileView and /api/system/fileDownload API endpoints, allowing attackers to read arbitrary files from the host filesystem without authentication by supplying path traversal sequences.
date: "2026-07-23T18:25:27Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - path-traversal
  - arbitrary-file-read
  - web-vulnerability
  - meshery
vendors:
  - Meshery
products:
  - Meshery (before 1.0.57)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can supply absolute paths or traversal sequences in the file parameter to read arbitrary files from the host filesystem without authentication.
    confidence_band: high
cves:
  - id: CVE-2026-65919
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65919
  - https://github.com/meshery/meshery/commit/ea83a26cb090b13be36c07cf24a99f8c637cc765
  - https://github.com/meshery/meshery/issues/20076
  - https://github.com/meshery/meshery/pull/20133
  - https://github.com/meshery/meshery/releases/tag/v1.0.57
  - https://www.vulncheck.com/advisories/meshery-unauthenticated-arbitrary-file-read-via-fileview-and-filedownload
rules:
  - title: Detects CVE-2026-65919 Exploitation - Meshery Path Traversal
    description: Detects CVE-2026-65919 exploitation attempts targeting Meshery's /api/system/fileView and /api/system/fileDownload endpoints with path traversal sequences or absolute paths in the 'file' parameter.
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

CVE-2026-65919 details a critical unauthenticated arbitrary file read vulnerability affecting Meshery software versions prior to 1.0.57. This flaw is present in the `/api/system/fileView` and `/api/system/fileDownload` API endpoints, which improperly handle user-supplied file parameters. Specifically, these endpoints pass arbitrary input directly to the `os.Open` function without implementing crucial path validation. This oversight allows an attacker to inject path traversal sequences (e.g., `../`, `../../`) or provide absolute file paths, enabling them to bypass directory restrictions and read any file on the host's underlying filesystem. The vulnerability is highly severe (CVSS 7.5 High) because it does not require authentication, making it accessible to any unauthenticated actor. The impact could range from exposure of sensitive configuration files and user data to system credentials, posing a significant risk to the integrity and confidentiality of the Meshery deployment.

## Attack Chain

1. An unauthenticated attacker sends an HTTP GET request to either the `/api/system/fileView` or `/api/system/fileDownload` endpoint.
2. The attacker includes a `file` parameter in the request's query string.
3. The value of the `file` parameter contains a path traversal sequence (e.g., `../../../../etc/passwd`) or an absolute path (e.g., `/etc/shadow`, `C:\\Windows\\System32\\drivers\\etc\\hosts`).
4. The vulnerable Meshery application processes the request, passing the malicious `file` parameter directly to the `os.Open` function without proper sanitization or validation.
5. The `os.Open` function attempts to read the file specified by the attacker's manipulated path outside the intended directory.
6. The content of the requested arbitrary file is returned in the HTTP response body to the attacker.
7. The attacker successfully exfiltrates sensitive system files, configuration, or credentials.

## Impact

Successful exploitation of CVE-2026-65919 allows an unauthenticated attacker to read any file on the server hosting Meshery. This could lead to the exposure of highly sensitive information, such as system configuration files, private keys, database credentials, user account details, and other proprietary data. While the NVD does not specify observed exploitation in the wild or victim counts, the ability for any unauthenticated actor to access arbitrary files without interaction makes this a critical data confidentiality risk. Compromised data could lead to further system compromise, privilege escalation, or lateral movement within an organization's network.

## Recommendation

* Patch CVE-2026-65919 immediately by updating Meshery to version 1.0.57 or later, as referenced in https://github.com/meshery/meshery/releases/tag/v1.0.57.
* Deploy the Sigma rule "Detects CVE-2026-65919 Exploitation - Meshery Path Traversal" to your SIEM to detect attempts to exploit the `/api/system/fileView` and `/api/system/fileDownload` endpoints with path traversal sequences.
* Ensure webserver logs (category: webserver) are collected and monitored for suspicious activity, particularly for requests containing unusual characters or pathing in URI query parameters.
