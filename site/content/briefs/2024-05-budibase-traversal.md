---
title: Budibase Path Traversal Vulnerability in Plugin Upload
slug: 2024-05-budibase-traversal
description: A path traversal vulnerability exists in Budibase versions prior to 3.33.4, allowing attackers with Global Builder privileges to delete arbitrary directories and write arbitrary files via crafted plugin uploads.
date: "2026-04-03T16:16:41Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - path-traversal
  - vulnerability
  - budibase
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-35214
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35214
rules:
  - title: Detect Budibase Plugin Upload Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability (CVE-2026-35214) in Budibase plugin uploads by identifying requests with directory traversal sequences in the filename.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
  - title: Detect Directory Deletion via rmSync
    description: Detects suspicious activity that could lead to directory deletion through rmSync following a path traversal.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1485
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Budibase, an open-source low-code platform, is vulnerable to a path traversal attack in versions prior to 3.33.4. This flaw resides in the plugin file upload endpoint (POST /api/plugin/upload), where the user-supplied filename is passed unsanitized to createTempFolder(). An attacker with Global Builder privileges can exploit this by crafting a multipart upload containing "../" sequences in the filename. This allows them to manipulate file paths, leading to arbitrary directory deletion via rmSync and arbitrary file write via tarball extraction. The attacker can write files to any filesystem path accessible by the Node.js process running Budibase. This vulnerability has been patched in version 3.33.4, and organizations using older versions are at risk.

## Attack Chain

1.  The attacker gains Global Builder privileges within a vulnerable Budibase instance (version < 3.33.4).
2.  The attacker crafts a multipart upload request targeting the `/api/plugin/upload` endpoint (POST request).
3.  Within the multipart form data, the attacker includes a filename parameter.
4.  The filename parameter contains path traversal sequences such as "../" to manipulate the file path.
5.  The Budibase application passes the unsanitized filename to the `createTempFolder()` function.
6.  The manipulated path is then used in subsequent file system operations, such as `rmSync` (for deleting directories) and tarball extraction.
7.  The attacker leverages `rmSync` with the manipulated path to delete arbitrary directories on the server.
8.  Alternatively, the attacker leverages tarball extraction to write arbitrary files to arbitrary locations on the server, leading to potential code execution or data compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker with Global Builder privileges to perform arbitrary file system operations on the Budibase server. This includes the ability to delete arbitrary directories, potentially causing denial of service, and write arbitrary files, potentially leading to remote code execution. The impact is significant as it could allow for complete system compromise if the attacker can overwrite critical system files or deploy malicious code. This is especially dangerous for organizations relying on Budibase for critical business applications.

## Recommendation

*   Immediately upgrade Budibase to version 3.33.4 or later to patch the CVE-2026-35214 vulnerability.
*   Monitor web server logs for POST requests to the `/api/plugin/upload` endpoint containing filenames with "../" sequences using the Sigma rule provided.
*   Implement strict access control policies to limit the number of users with Global Builder privileges within Budibase.
