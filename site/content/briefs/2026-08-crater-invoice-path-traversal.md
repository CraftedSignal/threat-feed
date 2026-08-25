---
title: Path Traversal in Crater Invoice Self-Update API
slug: 2026-08-crater-invoice-path-traversal
description: Crater Invoice versions through 6.0.6 contain a path traversal vulnerability in the self-update API that allows authenticated attackers to achieve remote code execution by uploading crafted ZIP archives.
date: "2026-08-25T14:08:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - path-traversal
  - rce
vendors:
  - Crater Invoice
products:
  - Crater Invoice (<= 6.0.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated company owners can supply crafted ZIP archives containing '../' sequences, allowing them to overwrite arbitrary files on the server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: By writing malicious PHP files to the web-accessible directory, an attacker can achieve remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-57863
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57863
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Crater Invoice to latest version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-57863
  mitigation_plan:
    - priority: immediate
      action: Disable self-update functionality
      owner: IT Operations
      addresses: CVE-2026-57863
      evidence: Source advisory
---

Crater Invoice through version 6.0.6 is susceptible to a path traversal vulnerability within its self-update API. The vulnerability stems from improper validation of filenames within ZIP archives processed by the application's unzip endpoint. An authenticated user with 'company owner' privileges can submit a ZIP file containing entries with directory traversal sequences (such as '../').

When the application passes these unsanitized entries to the PHP ZipArchive::extractTo() function, it performs file operations outside of the intended extraction directory. This allows an attacker to overwrite existing files or write new files to arbitrary locations on the host filesystem. By targeting the web-accessible public directory, an attacker can upload malicious PHP scripts to achieve remote code execution (RCE). This vulnerability represents a significant risk to hosted environments where attackers may already possess low-privileged administrative access.

## Impact

Successful exploitation allows authenticated attackers to achieve remote code execution on the underlying server. This could lead to full system compromise, unauthorized access to sensitive financial data stored within the application, and potential lateral movement into the hosting environment.

## Recommendation

- Upgrade Crater Invoice to a patched version beyond 6.0.6 as soon as it becomes available.
- Until patching is possible, restrict access to the self-update API or disable the module entirely if not required for standard operations.
- Monitor web server logs for suspicious POST requests to the self-update/unzip endpoints, specifically looking for anomalous request parameters or file upload patterns.
- Audit the web-accessible directories of the application for unexpected PHP files created during the update or management process.
