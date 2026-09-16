---
title: Arbitrary File Overwrite in Contest Gallery WordPress Plugin
slug: 2026-09-contest-gallery-overwrite
description: The Contest Gallery WordPress plugin is vulnerable to unauthenticated arbitrary file overwrite via the 'baseUrlForFacebook' parameter, allowing authenticated attackers to achieve remote code execution.
date: "2026-09-16T05:46:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:contestgallery:contest_gallery:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - rce
vendors:
  - Contest Gallery
products:
  - Contest Gallery (<= 32.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Contest Gallery plugin for WordPress is vulnerable to an unauthenticated arbitrary file overwrite flaw due to improper validation of the 'baseUrlForFacebook' parameter.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for authenticated attackers to overwrite known files which may lead to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-78088
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78088
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Contest Gallery to the version addressing CVE-2026-78088
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability notice
  mitigation_plan:
    - priority: immediate
      action: Review and restrict file system permissions for the web server user
      owner: IT Operations
      addresses: CVE-2026-78088
      evidence: General security best practices for WordPress plugins
---

The Contest Gallery WordPress plugin is affected by a critical vulnerability, tracked as CVE-2026-78088, which enables arbitrary file overwrite. The flaw resides in the 'baseUrlForFacebook' parameter, which lacks sufficient validation. While initially described as unauthenticated, the vulnerability can be leveraged by any attacker with subscriber-level access or higher to overwrite arbitrary files on the underlying web server. By overwriting critical PHP files or configuration files, an attacker can facilitate remote code execution (RCE). This vulnerability affects all versions of the plugin up to and including 32.0.1. Defenders should treat this as a high-priority risk for any WordPress site utilizing this plugin, as it provides a direct pathway for full site compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker to overwrite sensitive files within the WordPress installation directory. This can lead to the execution of arbitrary code with the privileges of the web server user, resulting in full site takeover, data exfiltration, or the deployment of persistent backdoors. The scope of impact is limited to WordPress installations running the affected plugin versions.

## Recommendation

* Update the Contest Gallery plugin to the latest available patched version immediately.
* Audit the WordPress installation directory for unauthorized changes to core files, particularly following any suspicious login activity.
* Restrict file system write permissions for the web server user to only those directories strictly required for operation, such as the /uploads folder.
* Monitor web access logs for requests containing unexpected directory traversal characters or malicious payloads targeting the 'baseUrlForFacebook' parameter.
