---
title: DumbAssets Path Traversal Vulnerability (CVE-2026-45230)
slug: 2026-05-dumbassets-path-traversal
description: DumbAssets version 1.0.11 is vulnerable to a path traversal vulnerability in the POST /api/delete-file endpoint, allowing unauthenticated attackers to delete arbitrary files, including critical files like server.js or package.json, resulting in denial of service.
date: "2026-05-18T18:19:06Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - path traversal
  - denial of service
  - cve-2026-45230
products:
  - DumbAssets
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
cves:
  - id: CVE-2026-45230
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45230
rules:
  - title: Detects CVE-2026-45230 Exploitation — DumbAssets Path Traversal
    description: Detects CVE-2026-45230 exploitation — POST requests to /api/delete-file with path traversal sequences in the filename.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1565
    data_sources:
      - webserver
  - title: Detects CVE-2026-45230 Exploitation — DumbAssets Attempted Path Traversal (status 4xx)
    description: Detects CVE-2026-45230 exploitation — Detects attempted path traversal attacks against DumbAssets by monitoring 4xx status codes when accessing the /api/delete-file endpoint with path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1565
    data_sources:
      - webserver
rules_count: 2
---

DumbAssets through version 1.0.11 is susceptible to a path traversal vulnerability identified as CVE-2026-45230. This flaw resides in the `POST /api/delete-file` endpoint, specifically within the `filesToDelete` array parameters. Exploitation requires no authentication by default, allowing remote attackers to delete arbitrary files on the system. By injecting `../` sequences, attackers can bypass directory boundary restrictions and traverse outside the intended application directory. The lack of proper input validation enables the deletion of critical files, such as `server.js` or `package.json`, leading to a complete denial of service (DoS) condition for the affected application.

## Attack Chain

1.  An unauthenticated attacker sends a `POST` request to the `/api/delete-file` endpoint.
2.  The attacker crafts the `filesToDelete` array within the request body to include filenames containing path traversal sequences (e.g., `../`).
3.  The application receives the `POST` request and processes the `filesToDelete` array without proper validation or sanitization of the provided filenames.
4.  The application attempts to resolve the file path based on the attacker-supplied input, leading to directory traversal outside of the intended application directory.
5.  The application proceeds to delete the files specified in the `filesToDelete` array based on the manipulated file paths.
6.  The attacker targets critical application files such as `server.js` or `package.json` using the path traversal vulnerability.
7.  The targeted critical files are successfully deleted by the application.
8.  The application experiences a denial of service due to the absence of essential files required for its operation.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to delete arbitrary files on the system. This can lead to the deletion of critical application files like `server.js` or `package.json`, resulting in a complete denial of service. Given the high CVSS score of 9.1, this vulnerability represents a significant risk. The absence of authentication by default makes exploitation straightforward, increasing the likelihood of successful attacks.

## Recommendation

*   Deploy the Sigma rule to detect malicious `POST` requests containing path traversal sequences targeting the `/api/delete-file` endpoint.
*   Inspect web server logs for `POST` requests to `/api/delete-file` with filename parameters containing `../` sequences.
*   Apply input validation and sanitization to the `filesToDelete` parameter in the `/api/delete-file` endpoint to prevent path traversal attacks.
*   Enforce authentication on the `/api/delete-file` endpoint to restrict access to authorized users only.
