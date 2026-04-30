---
title: Sharp Laravel Admin Panel Unrestricted File Upload Vulnerability
slug: 2026-06-sharp-file-upload-bypass
description: The code16/sharp Laravel admin panel package contains a vulnerability in its file upload endpoint that allows authenticated users to bypass all file type restrictions by manipulating the validation_rule parameter, potentially leading to Remote Code Execution (RCE) if the storage disk is configured to be publicly accessible.
date: "2026-03-25T20:03:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - laravel
  - file-upload
  - rce
  - code16/sharp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-fr76-5637-w3g9
  - https://github.com/code16/sharp
  - https://laravel.com/docs/13.x/filesystem
  - https://github.com/code16/sharp/pull/714
iocs:
  - type: url
    value: https://github.com/code16/sharp
  - type: url
    value: https://cwe.mitre.org/data/definitions/434.html
  - type: url
    value: https://github.com/code16/sharp
  - type: url
    value: https://laravel.com/docs/13.x/filesystem
  - type: url
    value: https://github.com/code16/sharp/pull/714
ioc_counts:
  url: 5
rules:
  - title: Detect Sharp File Upload Bypass Attempt
    description: Detects attempts to bypass file upload restrictions in Sharp Laravel admin panel by manipulating the validation_rule parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious PHP Upload via Sharp
    description: Detects the upload of PHP files to a webserver via the Sharp file upload endpoint.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `code16/sharp` Laravel admin panel package, specifically versions before 9.20.0, is vulnerable to unrestricted file upload. An authenticated user can manipulate the `validation_rule` parameter in the `/api/form/upload` endpoint to bypass file type restrictions. This vulnerability stems from insufficient server-side validation of the client-supplied `validation_rule`, which is directly passed to the Laravel validator. Successfully exploiting this vulnerability allows an attacker to upload arbitrary files, including PHP webshells, which can lead to remote code execution (RCE) if the storage disk is publicly accessible. The vulnerability was reported by zaurgsynv and has been patched in pull request #714. Defenders should ensure their Sharp instances are updated to version 9.20.0 or later, and restrict disk access.

## Attack Chain

1. An authenticated user logs into the Sharp Laravel admin panel.
2. The user navigates to a section of the application that utilizes the file upload functionality.
3. The user intercepts the HTTP request sent to the `/api/form/upload` endpoint.
4. The user modifies the request body, specifically the `validation_rule` parameter, setting it to `validation_rule[]=file`.
5. The modified request is sent to the server, bypassing MIME type and file extension checks.
6. The server processes the upload request, saving the arbitrary file (e.g., a PHP webshell) to the designated storage disk.
7. If the storage disk is publicly accessible, the attacker can access the uploaded file via a web browser.
8. The attacker executes the uploaded PHP webshell, achieving remote code execution (RCE) on the server.

## Impact

Successful exploitation of this vulnerability allows attackers to upload arbitrary files, including PHP webshells, to the affected server. This can lead to Remote Code Execution (RCE) if the server's storage disk is misconfigured to be publicly accessible. While default configurations prevent direct execution of uploaded PHP files, compromised servers can be leveraged for lateral movement, data exfiltration, or further malicious activities. This vulnerability impacts all installations of `code16/sharp` prior to version 9.20.0.

## Recommendation

*   Upgrade `code16/sharp` to version 9.20.0 or later to remediate CVE-2026-33687.
*   Ensure that the storage disk used for Sharp uploads is strictly private, as described in the Laravel filesystem documentation (https://laravel.com/docs/13.x/filesystem).
*   Deploy the Sigma rule "Detect Sharp File Upload Bypass Attempt" to identify attempts to exploit this vulnerability based on the `validation_rule` parameter.
*   Monitor web server logs for suspicious file uploads to the `/api/form/upload` endpoint, correlating with user activity and file extensions.
