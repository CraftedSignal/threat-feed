---
title: Arbitrary File Deletion in Link Library Plugin for WordPress
slug: 2026-08-link-library-arbitrary-file-deletion
description: An unauthenticated arbitrary file deletion vulnerability in the Link Library WordPress plugin (CVE-2026-18855) allows attackers to trigger server-side file removal via manipulated input during standard administrative moderation.
date: "2026-08-15T20:20:24Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WordPress
products:
  - Link Library
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can exploit this if the 'Delete local file on link deletion' option is enabled by an administrator.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This makes it possible for unauthenticated attackers to delete arbitrary files on the server, which can easily lead to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-18855
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18855
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Link Library plugin for all WordPress sites.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18855 remediation.
  mitigation_plan:
    - priority: immediate
      action: Disable 'Delete local file on link deletion' setting.
      owner: IT Operations
      addresses: CVE-2026-18855
      evidence: Plugin feature configuration allows exploit.
---

The Link Library plugin for WordPress (versions 7.9.4 and earlier) contains a critical security flaw in the ll_delete_link_fields function. The vulnerability stems from insufficient file path validation, allowing an unauthenticated attacker to supply a crafted path that the application will treat as a target for deletion.

For the attack to succeed, the administrator must have enabled the 'Delete local file on link deletion' feature, which is disabled by default. Once enabled, an attacker submits a malicious link to the application. When a site administrator performs the routine moderation task of permanently deleting that link, the application executes a deletion command against the attacker-supplied file path rather than the legitimate link file. Successful exploitation leads to the loss of critical system files, such as wp-config.php, which can subsequently be leveraged to achieve remote code execution (RCE) by forcing a reinstallation of the WordPress environment.

## Attack Chain

1. Attacker discovers a WordPress site using the Link Library plugin.
2. Attacker verifies the 'Delete local file on link deletion' option is active by submitting a link or observing site behavior.
3. Attacker submits a new link containing a path traversal payload or a path to a critical system file (e.g., wp-config.php) in the link's metadata/fields.
4. The site administrator logs into the WordPress dashboard.
5. The administrator views the list of pending or submitted links.
6. The administrator selects the malicious link and triggers a permanent delete operation.
7. The ll_delete_link_fields function executes the deletion using the attacker-controlled path.
8. Critical files are removed, destabilizing the application and potentially facilitating RCE.

## Impact

Successful exploitation results in the permanent deletion of arbitrary files on the hosting server. If key files such as wp-config.php are deleted, the integrity of the WordPress installation is compromised, often resulting in complete service downtime or an opportunity for the attacker to reconfigure the database credentials to gain full administrative access.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

- Update the Link Library plugin to the latest version immediately to resolve CVE-2026-18855.
- Disable the 'Delete local file on link deletion' setting in the Link Library configuration if it is not strictly required for business operations.
- Audit administrative moderation logs to identify abnormal link deletion patterns.
- Implement File Integrity Monitoring (FIM) on the web root to detect unexpected deletion events targeting wp-config.php or other sensitive system files.
- Monitor web server error logs for recurrent file access failures following link deletion tasks.
