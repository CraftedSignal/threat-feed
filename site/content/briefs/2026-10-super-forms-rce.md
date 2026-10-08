---
title: Arbitrary Directory Deletion in Super Forms WordPress Plugin
slug: 2026-10-super-forms-rce
description: Unauthenticated attackers can achieve arbitrary recursive directory deletion in Super Forms versions 6.3.316 and earlier by exploiting improper path validation in the submit_form function.
date: "2026-10-08T06:50:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:super_forms:super_forms:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - remote-deletion
  - web-application
vendors:
  - Super Forms
products:
  - Super Forms – Drag & Drop Form Builder (<= 6.3.316)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: This makes it possible for unauthenticated attackers to recursively delete arbitrary directories on the server.
    confidence_band: high
cves:
  - id: CVE-2026-17609
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17609
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all WordPress installations and identify versions of Super Forms in use.
      owner: SOC
      due: 24h
      evidence: Source confirms vulnerability in all versions up to 6.3.316.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Super Forms plugin to a version > 6.3.316.
      owner: IT Operations
      addresses: CVE-2026-17609
      evidence: Source identifies vulnerability in versions <= 6.3.316.
---

The Super Forms - Drag & Drop Form Builder plugin for WordPress (versions <= 6.3.316) is vulnerable to an arbitrary directory deletion vulnerability. The flaw exists within the submit_form function, where insufficient validation of JSON field declarations allows for path manipulation. Attackers can bypass the ABSPATH security guard by using the dirname() function to strip trailing slashes, effectively traversing the filesystem. If an administrator has enabled the 'Delete files from server after form submissions' setting, an unauthenticated attacker can recursively delete arbitrary directories, including the entire WordPress installation. This vulnerability poses a severe risk to service availability and data integrity for any WordPress site utilizing this plugin with the specific administrative setting enabled.

## Attack Chain

1. Attacker identifies a WordPress installation running a vulnerable version of the Super Forms plugin (<= 6.3.316).
2. Attacker verifies the plugin's 'Delete files from server after form submissions' setting is active, commonly found in plugin configurations.
3. Attacker crafts a malicious JSON payload targeting the submit_form function.
4. Attacker includes a directory path string designed to bypass the ABSPATH security guard via dirname() behavior.
5. Attacker sends an HTTP POST request to the plugin's submission endpoint containing the crafted JSON.
6. The application parses the malicious JSON and fails to validate the directory path against the intended schema.
7. The application executes the recursive deletion command on the provided target path.
8. Final objective is achieved as the target directory (e.g., WordPress root) is deleted from the server.

## Impact

Successful exploitation results in the recursive deletion of arbitrary directories on the host server. If the WordPress root directory is targeted, it results in complete application destruction and permanent data loss for the affected site. As the plugin is a popular form builder, numerous WordPress deployments globally are potentially at risk.

## Recommendation

Prioritized actions for security teams:
- Immediately upgrade the Super Forms plugin to the latest available patched version.
- Disable the 'Delete files from server after form submissions' feature in the Super Forms configuration if an immediate update is not possible.
- Audit existing form submissions and plugin logs for any unexpected HTTP POST requests directed at the submit_form endpoint that contain directory traversal patterns (e.g., '../').
- Ensure regular off-site backups are maintained to recover from potential data destruction events.
