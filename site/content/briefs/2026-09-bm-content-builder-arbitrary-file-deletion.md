---
title: Arbitrary File Deletion in BM Content Builder WordPress Plugin
slug: 2026-09-bm-content-builder-arbitrary-file-deletion
description: An arbitrary file deletion vulnerability in the BM Content Builder plugin for WordPress allows authenticated attackers to delete critical system files, potentially facilitating remote code execution.
date: "2026-09-22T08:34:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bm_content_builder_project:bm_content_builder:*:*:*:*:*:wordpress:*:*
tags:
  - vulnerability
  - web-application
  - wordpress
vendors:
  - WordPress
products:
  - BM Content Builder (< 3.17.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, to delete arbitrary files on the server
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: which can easily lead to remote code execution when the right file is deleted
    confidence_band: high
cves:
  - id: CVE-2025-1281
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-1281
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade BM Content Builder to 3.17.1 or later
      owner: IT Operations
      due: 48h
      evidence: Source states all versions up to 3.17.1 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade BM Content Builder to 3.17.1
      owner: IT Operations
      addresses: CVE-2025-1281
      evidence: NVD vulnerability details
---

The BM Content Builder plugin for WordPress contains an arbitrary file deletion vulnerability (CVE-2025-1281) resulting from insufficient file path validation within the `ux_cb_remove_layout_ajax()` and `ux_cb_tools_export_ajax()` functions. This vulnerability affects all plugin versions up to, and excluding, 3.17.1. Authenticated attackers with Subscriber-level privileges can trigger these functions to delete arbitrary files on the underlying web server. By deleting critical files such as `wp-config.php`, an attacker can force a WordPress site to enter its installation state, allowing them to gain control over the database, create a new administrative user, and achieve remote code execution. This represents a significant risk for WordPress environments using the BM Content Builder plugin.

## Impact

Successful exploitation allows for the deletion of arbitrary files on the web server hosting the WordPress site. If configuration files are removed, attackers can compromise site integrity, elevate privileges to administrator, or gain remote code execution, leading to complete server takeover or data loss.

## Recommendation

1. Upgrade the BM Content Builder plugin to version 3.17.1 or later immediately.
2. Audit WordPress installations for unauthorized administrative account creation, which often occurs following the deletion of `wp-config.php`.
3. Ensure that critical configuration files like `wp-config.php` have restrictive file system permissions that prevent the web server user from deleting them, where possible.
