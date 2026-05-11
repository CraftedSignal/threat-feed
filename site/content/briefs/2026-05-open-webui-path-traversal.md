---
title: Open WebUI Arbitrary File Write/Delete via Path Traversal
slug: 2026-05-open-webui-path-traversal
description: Open WebUI is vulnerable to path traversal (CVE-2026-44565), allowing attackers to upload files to arbitrary locations on the web server's filesystem and subsequently delete them due to insufficient filename sanitization in the `/ollama/models/upload` API endpoint.
date: "2026-05-11T14:05:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - file-deletion
  - web-application
vendors:
  - Open WebUI
products:
  - Open WebUI
affected_os:
  - Debian GNU/Linux 12
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-j3fw-wc48-29g3
  - https://github.com/open-webui/open-webui/blob/0399a69b73de9789c4221acedea70d528e1346c4/backend/apps/ollama/main.py#L1063-L1127
  - https://github.com/open-webui/open-webui/blob/0399a69b73de9789c4221acedea70d528e1346c4/backend/apps/ollama/main.py#L1070
rules:
  - title: Detect Open WebUI Path Traversal Upload Attempt
    description: Detects CVE-2026-44565 exploitation — HTTP POST requests to /ollama/models/upload with path traversal sequences in the filename parameter indicating a path traversal attempt.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
  - title: Detect Open WebUI File Deletion via Path Traversal
    description: Detects CVE-2026-44565 post-exploitation — suspicious process deletion events resulting from successful path traversal writing
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - impact
    techniques:
      - T1068
      - T1485
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Open WebUI version 0.1.105 is vulnerable to a path traversal vulnerability (CVE-2026-44565) affecting the `/ollama/models/upload` API route. This vulnerability, discovered by Taylor Pennington of KoreLogic, Inc., allows an attacker to upload files with arbitrary names to the server. Due to the lack of filename sanitization, an attacker can use dot-segments (../) to traverse the filesystem and write files to locations outside the intended upload directory. After the file is written successfully, the application attempts to remove the file using `os.remove(file_path)`, leading to arbitrary file deletion. This issue can lead to denial of service or potentially be chained with other vulnerabilities for more severe impact if the attacker can overwrite critical system files.

## Attack Chain

1. The attacker gains access to the Open WebUI HTTP interface.
2. The attacker crafts a malicious HTTP POST request to the `/ollama/models/upload` endpoint.
3. The request includes a file attachment with a filename containing path traversal sequences (e.g., `../../../../../../../tmp/DELETE_ME`).
4. The server receives the request and, without proper sanitization, constructs a file path using the attacker-controlled filename and saves the uploaded file to the specified location.
5. The server attempts to pass the file to another internal API.
6. Once the file is successfully processed by the internal API, the server attempts to remove the file using `os.remove(file_path)` with the attacker-controlled path.
7. Due to the path traversal vulnerability, the server deletes the file at the attacker-specified location on the filesystem.

## Impact

Successful exploitation of this vulnerability allows an attacker to delete arbitrary files on the system that the Open WebUI user has permissions to modify. This can lead to denial of service, data loss, or potentially be chained with other vulnerabilities to achieve arbitrary code execution if the attacker is able to overwrite critical system files. While the source mentions it might be possible to create a race condition, this was not validated.

## Recommendation

*   Apply the vendor-provided patch or upgrade to a version of Open WebUI greater than 0.1.105, which incorporates the recommended mitigation (https://github.com/advisories/GHSA-j3fw-wc48-29g3).
*   Deploy the Sigma rule "Detect Open WebUI Path Traversal Upload Attempt" to identify malicious requests attempting to exploit CVE-2026-44565.
*   Monitor web server logs for HTTP POST requests to the `/ollama/models/upload` endpoint containing filenames with path traversal sequences to identify potential exploitation attempts.
