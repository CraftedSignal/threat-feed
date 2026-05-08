---
title: Open WebUI Arbitrary File Upload and Path Traversal Vulnerability
slug: 2024-07-open-webui-upload-traversal
description: Open WebUI version 0.1.105 is vulnerable to arbitrary file upload and path traversal, allowing attackers to upload files to arbitrary locations on the web server's filesystem by exploiting a lack of filename validation.
date: "2024-07-03T18:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - file-upload
  - web-application
vendors:
  - Open WebUI
products:
  - Open WebUI (Formerly Ollama WebUI)
affected_os:
  - Debian GNU/Linux 12 (bookworm)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-9pgh-j74g-qj6m
rules:
  - title: Detect Open WebUI Path Traversal File Upload
    description: Detects CVE-2026-44566 exploitation — HTTP POST requests to the /rag/api/v1/doc endpoint with filenames containing path traversal sequences, indicating a path traversal attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Open WebUI Arbitrary File Uploads to Suspicious Locations
    description: Detects the creation of files in suspicious directories (e.g., /tmp, /var/tmp, /dev/shm) via Open WebUI indicating potential arbitrary file upload exploitation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Open WebUI version 0.1.105, formerly known as Ollama WebUI, is susceptible to an arbitrary file upload and path traversal vulnerability. Discovered by Jaggar Henry & Sean Segreti of KoreLogic, Inc. in March 2024, this flaw allows an attacker to upload files to arbitrary locations on the web server's filesystem. The vulnerability stems from the application's failure to properly validate or sanitize filenames during file uploads to the `/rag/api/v1/doc` endpoint. By exploiting this, malicious actors can use dot-segments (e.g., `../../`) in the file path to traverse out of the intended uploads directory. Successful exploitation enables the uploading of malicious models, such as pickled Python objects, or the modification of system files like `authorized_keys` for SSH access.

## Attack Chain

1. An attacker authenticates to the Open WebUI web interface.
2. The attacker crafts an HTTP POST request to the `/rag/api/v1/doc` endpoint, initiating a file upload.
3. The attacker includes a malicious filename in the multipart form data, containing path traversal sequences (e.g., `../../../../../../../../../../tmp/pwned.txt`).
4. The Open WebUI server receives the request and extracts the unsanitized filename from the HTTP POST request.
5. The server constructs a file path using the provided filename and the static `UPLOAD_DIR` variable.
6. The server proceeds to write the contents of the uploaded file to the constructed file path, effectively bypassing intended directory restrictions.
7. A malicious actor can overwrite existing system files, such as `.ssh/authorized_keys` for unauthorized system access.
8. Alternatively, an attacker uploads a malicious model as a pickled python object to achieve remote code execution.

## Impact

Successful exploitation of this vulnerability, identified as CVE-2026-44566, can lead to arbitrary code execution on the server. An attacker could gain unauthorized access to the system, potentially leading to data breaches, system compromise, or denial of service. The vulnerable version, 0.1.105, is actively exploitable, and organizations using this version are at risk. The targeted platform observed during analysis was Debian GNU/Linux 12.

## Recommendation

*   Upgrade Open WebUI to a version beyond 0.1.123 which addresses the CVE-2026-44566 vulnerability.
*   Implement input validation and sanitization on the server-side to prevent path traversal attacks during file uploads to mitigate the arbitrary file upload.
*   Deploy the Sigma rule "Detect Open WebUI Path Traversal File Upload" to identify exploitation attempts in web server logs.
*   Monitor web server logs for HTTP POST requests to the `/rag/api/v1/doc` endpoint with filenames containing path traversal sequences.
