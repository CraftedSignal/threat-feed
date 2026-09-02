---
title: Arbitrary File Deletion Vulnerability in SigmaForms Pro
slug: 2026-09-sigmaforms-pro-file-deletion
description: The SigmaForms Pro WordPress plugin is vulnerable to arbitrary file deletion via path traversal in the delete_submission_files function, allowing unauthenticated attackers to delete critical server files and potentially achieve remote code execution.
date: "2026-09-02T07:12:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:wordpress:sigmaforms_pro_ai_generated_forms:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - vulnerability
  - arbitrary-file-deletion
vendors:
  - WordPress
products:
  - SigmaForms Pro – AI Generated Forms (<= 1.4.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can exploit this via malicious input stored in submission records.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565.002
    technique_name: 'Data Manipulated: Stored Data'
    evidence: The malicious path traversal URL is submitted via form upload field and stored in the database.
    confidence_band: high
cves:
  - id: CVE-2026-78657
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78657
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade SigmaForms Pro plugin to version 1.4.12 or later.
      owner: IT Operations
      due: 24h
      evidence: Plugin version 1.4.11 and below are identified as vulnerable in CVE-2026-78657.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to latest version of SigmaForms Pro.
      owner: IT Operations
      addresses: CVE-2026-78657
      evidence: NVD vulnerability report.
---

The SigmaForms Pro - AI Generated Forms plugin for WordPress, in versions up to and including 1.4.11, is susceptible to an unauthenticated arbitrary file deletion vulnerability. This flaw resides in the delete_submission_files function, which fails to properly validate file paths during the deletion process. An attacker can inject a path traversal sequence into an upload field of a form. This malicious path is saved into the database within a submission record. When a site administrator later performs a cleanup or removes the submission record from the WordPress admin panel, the plugin processes the path and deletes the targeted file. 

By chaining this vulnerability with the deletion of critical WordPress configuration files such as wp-config.php, an attacker can force a re-installation of the application, potentially leading to remote code execution. Because the malicious trigger occurs during an administrative action, there is a delayed execution window between the initial malicious submission and the final file deletion.

## Attack Chain

1. Attacker identifies a WordPress site running SigmaForms Pro version 1.4.11 or lower.
2. Attacker submits a form containing an upload field.
3. Attacker inputs a path traversal string (e.g., ../../../wp-config.php) into the upload field payload.
4. The malicious string is stored in the database as a submission record by the plugin.
5. An administrator logs into the WordPress dashboard.
6. The administrator selects the malicious submission record and triggers a delete action.
7. The plugin executes delete_submission_files, invoking the file deletion logic with the attacker-supplied path.
8. The targeted file is deleted from the server filesystem.

## Impact

Successful exploitation allows unauthenticated attackers to delete arbitrary files on the WordPress server. This can cause significant service disruption or lead to full system compromise if attackers delete critical files like wp-config.php to initiate a site re-installation. The vulnerability affects all users running versions 1.4.11 or earlier of the SigmaForms Pro plugin.

## Recommendation

Prioritized actions for security teams:
- Update SigmaForms Pro - AI Generated Forms to the latest version (v1.4.12 or higher) to remediate CVE-2026-78657.
- Audit web server access logs for anomalous POST requests to form submission endpoints containing directory traversal patterns like '../'.
- Restrict file system permissions for the WordPress application user to prevent deletion of sensitive files outside of the intended upload directories.
