---
title: Path Traversal Vulnerability in Formwork BackupController
slug: 2026-10-formwork-path-traversal
description: Formwork prior to version 2.3.13 contains a path traversal vulnerability in the BackupController component allowing authenticated users to read or delete arbitrary files via base64-encoded payloads.
date: "2026-10-03T00:49:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getformwork:formwork:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - web-vulnerability
  - patch-management
vendors:
  - Formwork
products:
  - Formwork (< 2.3.13)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers with backup download or delete permission can supply a base64-encoded backslash-separated traversal payload that bypasses PHP basename on Linux to access files outside the backup directory.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565.002
    technique_name: 'Data Manipulated: Stored Data'
    evidence: Formwork before 2.3.13 contains a path traversal vulnerability in BackupController that allows authenticated panel users to read or delete arbitrary files.
    confidence_band: high
cves:
  - id: CVE-2026-104478
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104478
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Formwork to version 2.3.13
      owner: IT Operations
      due: 48h
      evidence: Source states Formwork before 2.3.13 contains the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 2.3.13
      owner: IT Operations
      addresses: CVE-2026-104478
      evidence: NVD vulnerability entry
---

Formwork versions prior to 2.3.13 are vulnerable to a path traversal vulnerability residing within the BackupController component. This vulnerability allows authenticated users who possess backup download or deletion permissions to escape the intended directory structure. By providing a base64-encoded, backslash-separated payload, an attacker can bypass the PHP basename validation logic on Linux-based installations. Successful exploitation permits an authenticated attacker to read sensitive configuration files or delete critical system files, potentially leading to full system compromise or service disruption. Defenders should prioritize updating to version 2.3.13 or later to remediate the underlying flaw in file handling.

## Impact

Successful exploitation of CVE-2026-104478 allows an authenticated user to perform arbitrary file reads or deletions. This impacts the integrity and confidentiality of the Formwork installation and underlying server data. If the service is running with elevated privileges, the impact can extend to the broader system environment.

## Recommendation

- Upgrade Formwork to version 2.3.13 or later immediately to patch CVE-2026-104478.
- Review access control lists for the administrative panel and restrict backup download and delete permissions to only the most trusted administrative accounts.
- Audit web server access logs for requests to the BackupController endpoint that contain unusual, encoded, or backslash-heavy string patterns.
