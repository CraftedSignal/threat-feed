---
title: Unauthenticated Arbitrary File Write in Saltcorn
slug: 2026-04-saltcorn-file-write
description: Unauthenticated attackers can exploit a vulnerability in Saltcorn versions prior to 1.4.5, 1.5.5, and 1.6.0-beta.4 to write arbitrary files and list directory contents on the server.
date: "2026-04-11T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - saltcorn
  - file-write
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40163
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40163
rules:
  - title: Detect Saltcorn Offline Changes Endpoint Abuse
    description: Detects suspicious POST requests to the /sync/offline_changes endpoint, indicative of CVE-2026-40163 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Saltcorn Upload Finished Endpoint Abuse
    description: Detects suspicious GET requests to the /sync/upload_finished endpoint, often used after exploiting CVE-2026-40163.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Saltcorn, a no-code database application builder, is vulnerable to an unauthenticated arbitrary file write vulnerability. Specifically, versions prior to 1.4.5, 1.5.5, and 1.6.0-beta.4 are affected. An attacker can leverage the POST `/sync/offline_changes` endpoint to create arbitrary directories and write a `changes.json` file with attacker-controlled content anywhere on the server's filesystem. Subsequently, the GET `/sync/upload_finished` endpoint allows an unauthenticated attacker to list directory contents and read specific JSON files. This combination of actions allows for complete control of the application, potentially leading to remote code execution. This vulnerability is resolved in Saltcorn versions 1.4.5, 1.5.5, and 1.6.0-beta.4.

## Attack Chain

1. The attacker sends a POST request to the `/sync/offline_changes` endpoint.
2. This POST request includes crafted JSON content intended to be written to a `changes.json` file.
3. The server creates arbitrary directories based on the attacker's specifications within the POST request.
4. The server writes the attacker-supplied JSON content to the `changes.json` file in the created directory.
5. The attacker sends a GET request to the `/sync/upload_finished` endpoint.
6. The GET request specifies the directory the attacker previously created.
7. The server lists the contents of the specified directory, including the `changes.json` file.
8. The attacker reads the contents of the `changes.json` file. Successful exploitation allows arbitrary file creation, directory listing, and reading of file contents.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to write arbitrary files and list directory contents on the Saltcorn server. This can lead to complete compromise of the application, including remote code execution, data theft, and denial of service. Given that Saltcorn is used in various sectors to build database applications, the potential impact is significant across multiple industries.

## Recommendation

*   Upgrade Saltcorn to version 1.4.5, 1.5.5, or 1.6.0-beta.4 or later to patch CVE-2026-40163.
*   Deploy the Sigma rule `Detect Saltcorn Offline Changes Endpoint Abuse` to detect suspicious POST requests to the `/sync/offline_changes` endpoint.
*   Deploy the Sigma rule `Detect Saltcorn Upload Finished Endpoint Abuse` to detect suspicious GET requests to the `/sync/upload_finished` endpoint.
*   Monitor web server logs for unexpected POST requests to `/sync/offline_changes` and GET requests to `/sync/upload_finished` (webserver log source).
