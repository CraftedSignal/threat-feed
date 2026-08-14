---
title: Path Traversal Vulnerability in Budibase
slug: 2026-08-budibase-traversal
description: Budibase versions before 3.40.0 are vulnerable to path traversal via maliciously crafted S3 object keys, allowing authenticated builders to perform arbitrary file writes during workspace export.
date: "2026-08-14T00:06:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webserver
  - path-traversal
  - cve-2026-72850
vendors:
  - Budibase
products:
  - server
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows an attacker to write arbitrary files to any path writable by the Budibase process, leading to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-72850
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72850
  - https://github.com/Budibase/budibase/security/advisories/GHSA-pxwc-66g3-5f27
  - https://www.vulncheck.com/advisories/budibase-before-arbitrary-file-write-via-path-traversal
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Budibase server to 3.40.0
      owner: IT Operations
      due: 24h
      evidence: Vendor patch availability for CVE-2026-72850
---

Budibase versions prior to 3.40.0 contain a critical path traversal vulnerability (CVE-2026-72850) affecting the handling of S3 object keys. The flaw originates in the application's failure to sanitize filenames provided during file uploads within the builder interface. When an authenticated user with builder privileges uploads a file containing directory traversal sequences (e.g., ../), these sequences are incorrectly preserved.

The vulnerability is triggered during the workspace export process. When the application processes these files, the lack of path validation allows the file contents to be written to arbitrary locations on the host filesystem that are writable by the Budibase service account. This allows an attacker to potentially overwrite configuration files, inject scripts, or place malicious binaries, leading to remote code execution or system compromise. Defenders should prioritize upgrading to version 3.40.0 or later to remediate the vulnerability.

## Attack Chain

1. Attacker authenticates to the Budibase builder interface with valid builder-level credentials.
2. Attacker initiates a file upload process for an S3-backed resource.
3. Attacker intercepts the upload request or modifies the request to include a filename containing directory traversal sequences (e.g., ../../etc/cron.d/malicious_job).
4. The Budibase application accepts and stores the malicious S3 object key without sanitization.
5. Attacker triggers a workspace export action within the application.
6. The backend export logic processes the stored malicious object keys.
7. The application writes the file content to the target directory on the filesystem outside of the intended temporary directory.
8. Attacker executes the injected content (e.g., via cron or web shell placement) to achieve remote code execution.

## Impact

The vulnerability allows for arbitrary file writes, which in a server environment typically leads to full remote code execution and complete system compromise. This poses a significant risk to the integrity and availability of the Budibase deployment. Given that this requires authenticated access, the impact is primarily targeted at organizations where builder accounts may be compromised or provisioned to untrusted users.

## Recommendation

* Upgrade Budibase server to version 3.40.0 or later immediately to patch CVE-2026-72850.
* Audit access logs for the Budibase application to identify any user accounts that have performed unusual export actions or bulk file uploads.
* Monitor filesystem activity on the Budibase server for unexpected file writes, particularly in directories outside of the application's designated data and temporary folders, using host-based instrumentation.
