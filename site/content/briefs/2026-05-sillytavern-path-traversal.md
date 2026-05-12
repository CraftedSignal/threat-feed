---
title: SillyTavern Unauthenticated Path Traversal in Extensions API
slug: 2026-05-sillytavern-path-traversal
description: SillyTavern versions 1.17.0 and earlier contain a path traversal vulnerability, CVE-2026-44650, in the `/api/extensions/delete` endpoint (and others), allowing an unauthenticated user to delete the entire extensions directory by providing '.' as the extension name, leading to data loss and potential remote exploitation via chaining with CVE-2025-59159.
date: "2026-05-12T22:24:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - web-application
  - CVE-2026-44650
vendors:
  - npm
products:
  - sillytavern (<= 1.17.0)
affected_os:
  - Windows 10
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
cves:
  - id: CVE-2025-59159
    cvss: 9.6
    epss: 9e-05
references:
  - https://github.com/advisories/GHSA-886q-f44j-h6wh
  - https://www.npmjs.com/package/sanitize-filename
  - CVE-2025-59159
rules:
  - title: Detect SillyTavern Path Traversal Attempt via Extension Deletion
    description: Detects CVE-2026-44650 exploitation — attempts to delete the entire extensions directory in SillyTavern by sending a POST request to /api/extensions/delete with a '.' as the extensionName parameter.
    platform: sigma
    severity: critical
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
  - title: Detect SillyTavern Path Traversal Attempt via Other Endpoints
    description: Detects CVE-2026-44650 exploitation — attempts to exploit the path traversal vulnerability in SillyTavern on the `/api/extensions/update`, `/api/extensions/version`, `/api/extensions/branches`, and `/api/extensions/switch` endpoints using '.' as the extensionName.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
rules_count: 2
---

SillyTavern, a popular open-source AI storytelling application, is vulnerable to a path traversal attack (CVE-2026-44650) affecting versions 1.17.0 and earlier. The vulnerability resides in the extensions API endpoints, specifically `/api/extensions/delete`, `/api/extensions/update`, `/api/extensions/version`, `/api/extensions/branches`, and `/api/extensions/switch`. Due to insufficient validation and sanitization of the `extensionName` parameter, an unauthenticated attacker can send a crafted HTTP POST request with `extensionName: "."` to these endpoints, causing the application to recursively delete the entire extensions directory. This vulnerability is exploitable by anyone with network access to the SillyTavern instance in its default configuration (basicAuthMode: false). Furthermore, this can be chained with CVE-2025-59159 (DNS rebinding) to enable remote exploitation.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable SillyTavern instance running version 1.17.0 or earlier.
2. The attacker crafts an HTTP POST request to the `/api/extensions/delete` endpoint (or `/update`, `/version`, `/branches`, `/switch`).
3. The attacker includes a JSON payload in the request body with the `extensionName` parameter set to `.`.
4. The application receives the request and proceeds to the `src/endpoints/extensions.js` file.
5. The application's validation logic incorrectly allows the `.` value because the check `!request.body.extensionName` occurs before sanitization.
6. The `sanitize-filename` function converts the `.` to an empty string "".
7. The `path.join(basePath, "")` function concatenates the base extensions path with the empty string, resulting in the `basePath` itself.
8. The application then executes `fs.promises.rm(extensionPath, { recursive: true })`, effectively deleting the entire extensions directory (e.g., `data\default-user\extensions\`).

## Impact

Successful exploitation of this path traversal vulnerability (CVE-2026-44650) leads to the complete and unrecoverable removal of all installed third-party extensions from the SillyTavern instance. The default configuration of SillyTavern does not require authentication, making the vulnerability easily exploitable. If the application is configured with `global: true` and admin privileges, the attacker can also delete the global extensions directory, affecting all users. The vulnerability can be combined with CVE-2025-59159 (DNS rebinding) to enable unauthenticated remote exploitation from a malicious website. The CVSS score is 9.1 (Critical).

## Recommendation

*   Apply the suggested fix from the advisory to the `/api/extensions/delete`, `/api/extensions/update`, `/api/extensions/version`, `/api/extensions/branches`, and `/api/extensions/switch` endpoints, ensuring that validation occurs *after* sanitization and including a path traversal guard (see "Suggested Fix" in the content).
*   Deploy the Sigma rule `Detect SillyTavern Path Traversal Attempt via Extension Deletion` to detect attempts to exploit CVE-2026-44650 targeting the `/api/extensions/delete` endpoint based on the `extensionName` parameter value.
*   Deploy the Sigma rule `Detect SillyTavern Path Traversal Attempt via Other Endpoints` to detect attempts to exploit CVE-2026-44650 on the `/api/extensions/update`, `/api/extensions/version`, `/api/extensions/branches`, and `/api/extensions/switch` endpoints.
*   Monitor web server logs for HTTP POST requests to the extensions API endpoints with suspicious `extensionName` values as an indicator of potential exploitation.
