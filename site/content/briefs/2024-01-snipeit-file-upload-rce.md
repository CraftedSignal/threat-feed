---
title: Snipe-IT File Upload Vulnerability Leads to Remote Code Execution (CVE-2026-37709)
slug: 2024-01-snipeit-file-upload-rce
description: Snipe-IT versions prior to 8.4.1 are vulnerable to remote code execution due to insecure permissions on file uploads, where an attacker can upload arbitrary files and execute code on the server.
date: "2026-05-08T23:04:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote code execution
  - file upload
  - insecure permissions
  - asset management
  - CVE-2026-37709
vendors:
  - grokability
products:
  - snipe-it (< 8.4.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-37709
    cvss: 9.8
    epss: 0.00214
references:
  - https://github.com/advisories/GHSA-xg82-2hrv-hf64
rules:
  - title: Detect CVE-2026-37709 Exploitation — SnipeIT Malicious File Upload
    description: Detects CVE-2026-37709 exploitation — Monitors for HTTP POST requests to the file upload endpoint with suspicious file extensions.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-37709 Exploitation — SnipeIT Uploaded File Controller Access
    description: Detects CVE-2026-37709 exploitation — Monitors for HTTP requests accessing the UploadedFilesController, indicating potential exploit attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Snipe-IT, a web-based IT asset management system, is vulnerable to a critical file upload vulnerability (CVE-2026-37709) affecting versions up to 8.4.0. This vulnerability stems from insufficient permission checks in the `app/Http/Controllers/Api/UploadedFilesController.php` component. Specifically, the API endpoint `/api/v1/{object_type}/{id}/files` allows users with "view" permissions, rather than the necessary "write" permissions, to upload files. Successful exploitation of this vulnerability can lead to arbitrary code execution on the server. The vulnerability was patched after the 2026-03-10 commit 676a9958 and released in version 8.4.1. This poses a significant risk to organizations using vulnerable Snipe-IT instances, potentially allowing attackers to compromise the entire system.

## Attack Chain

1.  An attacker identifies a vulnerable Snipe-IT instance running a version prior to 8.4.1.
2.  The attacker authenticates to the Snipe-IT instance with user credentials that have "view" permissions for assets, consumables, or other managed objects.
3.  The attacker crafts a malicious HTTP POST request to the `/api/v1/{object_type}/{id}/files` endpoint, replacing `{object_type}` and `{id}` with valid values for an existing asset or consumable.
4.  The POST request includes a file containing malicious code, such as a PHP webshell, disguised as a seemingly harmless file type (e.g., image).
5.  The Snipe-IT application, due to insufficient permission checks, accepts the file upload and stores it on the server.
6.  The attacker determines the full path to the uploaded file on the server.
7.  The attacker crafts a new HTTP request to execute the uploaded file, triggering the malicious code.
8.  The attacker achieves remote code execution on the Snipe-IT server, potentially gaining full control of the system and sensitive data.

## Impact

Successful exploitation of CVE-2026-37709 can lead to complete compromise of the Snipe-IT server. An attacker can gain unauthorized access to sensitive asset information, modify inventory data, and potentially pivot to other systems within the network. Given the critical nature of asset management systems, this vulnerability poses a severe risk to organizations of all sizes and across various sectors. The attacker could potentially steal intellectual property, disrupt operations, or launch further attacks from the compromised server.

## Recommendation

*   Upgrade Snipe-IT installations to version 8.4.1 or later to remediate CVE-2026-37709, as this version contains the necessary permission checks in the `app/Http/Controllers/Api/UploadedFilesController.php` component.
*   Deploy the Sigma rule "Detect CVE-2026-37709 Exploitation — SnipeIT Malicious File Upload" to detect suspicious POST requests to the `/api/v1/{object_type}/{id}/files` endpoint.
*   Monitor web server logs for HTTP POST requests to the `/api/v1/{object_type}/{id}/files` endpoint with filenames that contain suspicious extensions or patterns to identify potential exploitation attempts.
