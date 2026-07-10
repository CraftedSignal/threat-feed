---
title: Daptin Unauthenticated Path Traversal and Zip Slip Vulnerability
slug: 2024-01-03-daptin-path-traversal
description: Daptin versions up to and including v0.11.3 are vulnerable to unauthenticated path traversal and zip slip attacks via the cloudstore.file.upload action, allowing arbitrary file write and potential remote code execution.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - zip-slip
  - remote-code-execution
  - daptin
vendors:
  - Daptin
products:
  - Daptin
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1555
    technique_name: Credentials on Shared Network Drive
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Shared Network Drive
references:
  - https://github.com/advisories/GHSA-9cp7-j3f8-p5jx
rules:
  - title: Detect Daptin Path Traversal in Upload
    description: Detects attempts to exploit the Daptin path traversal vulnerability by monitoring HTTP requests to the cloudstore.file.upload action containing path traversal sequences in the filename.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 1
---

Daptin, a cloud application, is susceptible to a critical vulnerability affecting versions up to and including v0.11.3. The vulnerability resides in the `cloudstore.file.upload` action within the `server/actions/action_cloudstore_file_upload.go` component. This flaw stems from the insufficient validation of user-supplied filenames during file uploads, enabling unauthenticated attackers to perform path traversal and zip slip attacks. By manipulating filenames, attackers can write arbitrary files to the server's file system. This can lead to overwriting critical system files, injecting malicious code, and ultimately achieving remote code execution. The unauthenticated nature of the vulnerability makes it easily exploitable and poses a significant risk to Daptin deployments.

## Attack Chain

1. An unauthenticated attacker sends a malicious HTTP request to the Daptin server targeting the `cloudstore.file.upload` action.
2. The request includes a crafted filename containing path traversal sequences (e.g., `../`, `..\\`).
3. The Daptin server's `action_cloudstore_file_upload.go` processes the request without proper validation of the filename.
4. The server attempts to write the uploaded file to a location derived from the malicious filename.
5. Due to the path traversal sequences, the file is written to an arbitrary location on the server's file system, outside the intended upload directory.
6. If the uploaded file is a ZIP archive, the attacker can further exploit the vulnerability using a zip slip attack by including filenames with directory traversal characters inside the archive.
7. The server extracts the files from the ZIP archive, writing them to arbitrary locations based on the manipulated filenames inside the archive.
8. The attacker overwrites critical system files or injects malicious code (e.g., a web shell) leading to remote code execution on the Daptin server.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to write arbitrary files to the Daptin server's file system. This can lead to several severe consequences, including: overwriting critical system files, injecting malicious code (e.g., web shells), gaining unauthorized access to sensitive data, and ultimately achieving remote code execution. Given the CVSS score of 10.0, this vulnerability poses a critical risk to organizations using affected versions of Daptin. Without proper patching or workarounds, affected systems are highly susceptible to compromise.

## Recommendation

*   Upgrade to a patched version of Daptin as soon as it is released to remediate the underlying vulnerability (reference: Patches section).
*   Implement temporary mitigation by restricting access to the `cloudstore.file.upload` action through authentication and authorization controls until a patch is available (reference: Workarounds section).
*   Deploy the Sigma rule `Detect Daptin Path Traversal in Upload` to monitor for suspicious file upload requests with path traversal sequences in the filename (reference: Sigma rule).
