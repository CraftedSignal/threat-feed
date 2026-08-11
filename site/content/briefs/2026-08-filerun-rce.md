---
title: OS Command Injection in FileRun Thumbnail Generation
slug: 2026-08-filerun-rce
description: FileRun versions up to 2026.2.0 contain a command injection vulnerability in the thumbnail generation component allowing authenticated attackers to execute arbitrary code.
date: "2026-08-11T21:52:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - command-injection
  - file-upload
vendors:
  - FileRun
products:
  - FileRun (<= 2026.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The thumbnail generation system passes filenames wrapped in shell double-quotes directly to exec() without escapeshellarg() sanitization, allowing filenames such as $(PAYLOAD).mp4 to survive the filename sanitizer and be evaluated as shell commands.
    confidence_band: high
cves:
  - id: CVE-2026-14863
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14863
rules:
  - title: Detects CVE-2026-14863 Exploitation - Command Injection via Thumbnail Generator
    description: Detects potential command injection attempts by monitoring thumbnail generation tools for suspicious command line arguments containing shell metacharacters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch FileRun to the version addressing CVE-2026-14863
      owner: IT Operations
      due: 48h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Restrict file upload types and sanitize filenames at the web application layer
      owner: IT Operations
      addresses: CVE-2026-14863
      evidence: Source describes vulnerability in thumbnail filename processing
---

FileRun versions up to and including 2026.2.0 contain an OS command injection vulnerability located within the application's thumbnail generation system. The vulnerability exists because the application passes file names containing shell command substitution sequences directly to system-level execution functions without adequate sanitization or escaping via `escapeshellarg()`. 

An authenticated attacker can exploit this by uploading a specially crafted file with a malicious filename (e.g., using syntax like `$(PAYLOAD).mp4`). When the system attempts to generate a thumbnail for the uploaded file using back-end utilities such as ffmpeg, ImageMagick, vips, or stl-thumb, the shell interprets the embedded payload. This allows for remote code execution on the host server under the privileges of the web application user. This flaw is particularly significant for environments where file uploads are permitted for authenticated users.

## Impact

Successful exploitation allows an authenticated attacker to achieve arbitrary remote code execution on the server. This can lead to full system compromise, data exfiltration, or lateral movement within the environment. All deployments of FileRun version 2026.2.0 and earlier are susceptible.

## Recommendation

* Upgrade FileRun to the latest version as soon as a patch is available.
* Identify and audit user upload directories for files containing shell metacharacters or suspicious extensions.
* Monitor webserver logs for requests to thumbnail generation or upload endpoints that exhibit unusual query parameters or filename patterns.
* Deploy the Sigma rule below to detect attempts to exploit CVE-2026-14863 by identifying shell injection patterns in the process lineage of thumbnail generation utilities.
