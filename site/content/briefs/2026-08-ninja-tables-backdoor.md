---
title: Supply Chain Compromise of Ninja Tables Pro via Malicious Update
slug: 2026-08-ninja-tables-backdoor
description: Ninja Tables Pro version 5.2.11 was compromised via a supply chain attack involving a decommissioned update server that distributed a tampered plugin build containing a PHP backdoor.
date: "2026-08-13T16:56:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - wordpress
  - webshell
  - cve-2026-73533
vendors:
  - Ninja Tables
products:
  - Ninja Tables Pro (5.2.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ninja Tables Pro 5.2.11 contains an embedded malicious code vulnerability introduced via a tampered plugin build.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
    evidence: dropped persistent PHP files in mu-plugins and uploads directories
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1136.001
    technique_name: 'Create Account: Local Account'
    evidence: installed a passwordless administrator account
    confidence_band: high
cves:
  - id: CVE-2026-73533
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73533
rules:
  - title: Detect Suspicious File Creation in mu-plugins
    description: Detects the creation of PHP files in the mu-plugins directory, a common persistence technique for WordPress backdoors.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Scan all web server directories for the existence of app/Library/updater/NinjaTableDataSync.php.
      owner: SOC
      due: 24h
      evidence: Source identifies this specific file as the backdoor component.
  hunt_leads:
    - lead: Search for recently created or modified files in the /wp-content/mu-plugins/ directory.
      technique_id: T1547.001
      data_needed:
        - File system logs / FIM logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of persistence in mu-plugins.
  mitigation_plan:
    - priority: immediate
      action: Remove Ninja Tables Pro 5.2.11 and perform a clean install from a verified, known-good source.
      owner: IT Operations
      addresses: CVE-2026-73533
      evidence: Vulnerability exists specifically in version 5.2.11.
---

Ninja Tables Pro version 5.2.11 was compromised through a supply chain attack involving a decommissioned update server. This server was leveraged to distribute a tampered plugin build to unsuspecting users. The malicious build contains a rogue PHP file, located at app/Library/updater/NinjaTableDataSync.php, which facilitates unauthorized access by establishing a backdoor REST API endpoint. 

Once installed, the malicious code performs several actions to ensure persistence and control over the compromised WordPress environment. It drops persistent PHP files within the 'mu-plugins' and 'uploads' directories, creates a passwordless administrator account, and registers scheduled tasks that persist even if the primary plugin is removed. Defenders must audit their WordPress installations for the presence of this specific file and check for unauthorized administrator accounts or unrecognized files in the 'mu-plugins' directory.

## Attack Chain

1. Attacker gains control of or spoofs a decommissioned update server associated with the Ninja Tables plugin.
2. The compromised server pushes a tampered version of the Ninja Tables Pro 5.2.11 plugin to clients.
3. The plugin installation executes the payload, dropping the malicious file app/Library/updater/NinjaTableDataSync.php.
4. The malicious PHP code activates a backdoor REST API endpoint to receive external commands.
5. The backdoor drops additional persistent PHP payloads into the WordPress 'mu-plugins' and 'uploads' folders.
6. The script creates a new, passwordless administrator account to ensure future access.
7. The script registers scheduled tasks (cron jobs) to maintain persistence across plugin updates or removals.
8. The attacker uses the established backdoor and administrator account to facilitate ongoing unauthorized access and system manipulation.

## Impact

The vulnerability allows for full, unauthenticated administrative control over the affected WordPress environment. This enables the attacker to exfiltrate data, modify site content, or use the compromised site as a platform for further attacks. Given the nature of the persistence mechanisms, cleanup requires manual removal of malicious files and database entries beyond simply updating or deleting the affected plugin.

## Recommendation

- Perform a file integrity audit on all WordPress installations using Ninja Tables Pro to identify the existence of app/Library/updater/NinjaTableDataSync.php.
- Audit the 'mu-plugins' directory for any unauthorized PHP files that were not manually installed by your organization.
- Review all WordPress user accounts for suspicious, passwordless, or unexpected administrator-level accounts.
- Remove any scheduled tasks (WP-Cron) associated with the Ninja Tables plugin and verify no other rogue tasks remain.
- Use the Sigma rule provided below to monitor for the creation or execution of files within the 'mu-plugins' path, as this is a common persistence location for web-based attacks.
