---
title: Remote Sunrise Helper for Windows 2026.14 - Unauthenticated File/Directory Listing
slug: 2026-05-remote-sunrise-helper-file-listing
description: A local exploit has been published for Remote Sunrise Helper for Windows 2026.14, detailing an unauthenticated file/directory listing vulnerability. Successful exploitation allows unauthenticated attackers to list files and directories on the affected system.
date: "2026-05-15T12:52:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - unauthenticated-access
  - file-listing
  - windows
vendors:
  - rs
products:
  - Remote Sunrise Helper for Windows (2026.14)
affected_os:
  - Windows 10
  - Windows 11
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
references:
  - https://www.exploit-db.com/exploits/52566
rules:
  - title: Detect Unauthenticated File Listing Attempt in Remote Sunrise Helper
    description: Detects attempts to exploit the unauthenticated file listing vulnerability in Remote Sunrise Helper by monitoring requests to the /api/listFiles endpoint without authentication.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
  - title: Detect Attempt to Get Version without Auth in Remote Sunrise Helper
    description: Detects attempts to determine authentication requirements by monitoring requests to the /api/getVersion endpoint.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
rules_count: 2
---

A public exploit has been published on Exploit-DB (EDB-52566) detailing an unauthenticated file/directory listing vulnerability in Remote Sunrise Helper for Windows 2026.14. The vulnerable software exposes an API endpoint `/api/listFiles` which can be accessed without authentication to list directory contents on the target Windows system. The exploit leverages HTTP GET requests to this endpoint, potentially allowing attackers to enumerate sensitive files and directories. The availability of this exploit increases the risk to systems running the affected version of Remote Sunrise Helper.

## Attack Chain

1. Attacker identifies a target system running Remote Sunrise Helper for Windows 2026.14 on port 49762.
2. The attacker crafts an HTTP GET request to `https://<target_ip>:49762/api/getVersion` to determine if authentication is required.
3. If the response indicates that authentication is not required ( `"requires.auth": False`), the attacker proceeds to the next step.
4. The attacker crafts an HTTP GET request to `https://<target_ip>:49762/api/listFiles` with the `X-HostName`, `X-ClientToken`, and `X-HostFullModel` headers set to arbitrary values.
5. To list a specific directory, the attacker URL-encodes the path and includes it in the request to `https://<target_ip>:49762/api/listFiles=<encoded_path>`.
6. The server responds with a JSON payload containing a list of files and directories within the requested path.
7. The attacker parses the JSON response to enumerate files and directories on the target system.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to list files and directories on the Windows system running Remote Sunrise Helper 2026.14. This information can be used to discover sensitive information, identify potential targets for further exploitation, or gather intelligence about the system's configuration. The impact is information disclosure, potentially leading to further compromise of the affected system.

## Recommendation

*   Apply appropriate access controls or remove the affected software.
*   Monitor webserver logs for requests to the `/api/listFiles` endpoint from unusual source IPs, as detailed in the overview.
*   Deploy the Sigma rule to detect unauthenticated access to the `/api/listFiles` endpoint as outlined below.
