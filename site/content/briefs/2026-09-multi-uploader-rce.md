---
title: CVE-2026-87796 - Arbitrary File Upload in Multi Uploader for Gravity Forms
slug: 2026-09-multi-uploader-rce
description: The Multi Uploader for Gravity Forms WordPress plugin is vulnerable to unauthenticated arbitrary file upload due to improper validation in the move_file function, enabling potential remote code execution.
date: "2026-09-17T05:53:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:multi_uploader_for_gravity_forms_project:multi_uploader_for_gravity_forms:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - Multi Uploader for Gravity Forms (<= 1.1.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-87796
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87796
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit WordPress plugin inventory for Multi Uploader for Gravity Forms and update to the patched version.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-87796 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Disable the vulnerable plugin if no update is available.
      owner: IT Operations
      addresses: CVE-2026-87796
      evidence: Arbitrary File Upload vulnerability in move_file function
---

The Multi Uploader for Gravity Forms plugin for WordPress (versions up to and including 1.1.9) contains a critical vulnerability (CVE-2026-87796) in its chunked upload handling logic. The vulnerability resides in the move_file function, which fails to adequately validate the type of files being processed during the upload sequence. 

This flaw allows an unauthenticated remote attacker to bypass intended file type restrictions and upload arbitrary files, such as malicious PHP scripts, to the web server directory. By successfully uploading a web shell, an attacker can achieve remote code execution, leading to full site compromise. Defenders should prioritize patching or disabling the plugin until an update is applied, as this vulnerability provides a direct pathway for unauthenticated attackers to gain persistent access to the server environment.

## Impact

Successful exploitation of CVE-2026-87796 grants an unauthenticated attacker the ability to execute arbitrary code on the underlying web server. This can lead to total site takeover, data exfiltration, and the deployment of additional malicious payloads. All WordPress sites utilizing the Multi Uploader for Gravity Forms plugin version 1.1.9 or earlier are at risk.

## Recommendation

* Immediately update the Multi Uploader for Gravity Forms plugin to the latest version once available to address the move_file function validation logic.
* If no patch is available, deactivate the plugin to mitigate the risk of arbitrary file upload.
* Monitor web server logs for suspicious POST requests targeting chunked upload endpoints.
* Implement file integrity monitoring (FIM) on the WordPress upload directories to detect unauthorized file creations or extensions (e.g., .php, .phtml).
