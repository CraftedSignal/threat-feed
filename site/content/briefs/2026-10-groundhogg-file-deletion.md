---
title: Arbitrary File Deletion in Groundhogg WordPress Plugin
slug: 2026-10-groundhogg-file-deletion
description: The Groundhogg WordPress plugin contains an arbitrary file deletion vulnerability in the copy_file function that allows authenticated users with specific capabilities to remove critical server files.
date: "2026-10-16T06:25:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:groundhogg:crm_newsletters_and_marketing_automation_plugin:*:*:*:*:*:*:*:*
tags:
  - web-application
  - wordpress
  - cve-2026-109221
vendors:
  - Groundhogg
products:
  - Groundhogg — CRM, Newsletters, and Marketing Automation plugin (<= 4.9.3)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1485
    technique_name: Data Destruction
    evidence: This makes it possible for authenticated attackers, with Sales Representative-level access and above, to delete arbitrary files on the server
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: which can easily lead to remote code execution when the right file is deleted (such as wp-config.php)
    confidence_band: high
cves:
  - id: CVE-2026-109221
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109221
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Groundhogg plugin to the latest version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109221 remediation
  enrichment_needed:
    - item: Exploit path mapping
      owner: CTI
      reason: Need to identify the specific plugin endpoint that invokes copy_file to create a detection rule
      evidence: Lack of specific endpoint path in source
  mitigation_plan:
    - priority: immediate
      action: Remove 'import_contacts' capability from non-admin roles
      owner: IT Operations
      addresses: CVE-2026-109221
      evidence: The vulnerability is exploitable by any user holding the plugin-defined import_contacts capability
---

Groundhogg - CRM, Newsletters, and Marketing Automation plugin for WordPress is susceptible to an arbitrary file deletion vulnerability (CVE-2026-109221). The issue stems from insufficient input validation within the 'copy_file' function in plugin versions up to and including 4.9.3. The vulnerability is accessible to authenticated users possessing the 'import_contacts' capability, a permission granted by default to the 'Sales Representative' role. By manipulating file paths, an attacker can delete sensitive files from the WordPress installation directory. Successful exploitation allows for the deletion of critical files such as 'wp-config.php', which can be leveraged to reset the installation process or facilitate remote code execution by bypassing security configurations. Defenders should prioritize auditing the permissions associated with the 'Sales Representative' role and patching to the version addressing this path validation flaw.

## Impact

The vulnerability allows authenticated attackers with limited administrative privileges to impact the integrity and availability of the WordPress site. Deletion of 'wp-config.php' forces the application to return to an uninitialized state, permitting unauthorized attackers to reconfigure the database connection and take full control of the web application and underlying server environment.

## Recommendation

* Patch the Groundhogg plugin to the latest version immediately to resolve the path validation flaw in 'copy_file'.
* Audit WordPress user roles and capabilities to identify and restrict accounts assigned the 'Sales Representative' role or the 'import_contacts' capability.
* Monitor web server access logs for anomalous POST requests targeting the plugin's file manipulation endpoints.
