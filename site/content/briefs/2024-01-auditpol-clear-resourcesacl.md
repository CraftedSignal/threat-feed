---
title: Windows Auditpol ResourceSACL Clearing for Defense Evasion
slug: 2024-01-auditpol-clear-resourcesacl
description: Adversaries may clear the global object access auditing policy using `auditpol.exe` with the `/resourceSACL` flag and either `/clear` or `/remove` arguments to evade detection by removing audit configurations.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
vendors:
  - Splunk
  - Microsoft
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Windows
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-resourcesacl
rules:
  - title: Detect Auditpol ResourceSACL Clearing
    description: Detects the use of auditpol.exe to clear the resourceSACL policy, which can be used to evade detection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Detect Auditpol Execution with Suspicious Arguments
    description: Detects execution of auditpol.exe with potentially malicious arguments.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers, including red teams, may attempt to disable or modify security policies to evade detection. The Windows command-line tool `auditpol.exe` can be abused to clear or remove global object access audit policies. This involves using the `/resourceSACL` flag combined with the `/clear` or `/remove` arguments. By doing so, adversaries aim to limit the data available for security monitoring, making it harder to detect their activities and maintain persistence. The clearing of `resourceSACL` configurations removes auditing for access to specific objects or resources, potentially allowing attackers to operate without generating audit logs that could expose their actions.

## Attack Chain

1.  Attacker gains initial access to a system via exploitation or credential compromise.
2.  The attacker elevates privileges to Administrator or SYSTEM to perform actions requiring elevated permissions.
3.  Attacker executes `auditpol.exe` with the `/resourceSACL` flag and the `/clear` argument.
4.  `auditpol.exe` process modifies the system's audit policy settings related to global object access.
5.  The targeted `resourceSACL` configurations are cleared, removing auditing for specific objects or resources.
6.  Attacker validates the removal of audit policies by querying the configuration using `auditpol.exe /get /category:*`.
7.  With auditing disabled for those resources, attacker performs malicious actions such as lateral movement, data exfiltration, or installing malware.

## Impact

Successful execution of this technique allows attackers to operate with reduced visibility. This can lead to delayed detection of malicious activities, increased dwell time, and greater potential for data breaches or system compromise. This impacts organizations relying on Windows event logging for security monitoring, especially those using global object access auditing to detect unauthorized access to sensitive data or resources.

## Recommendation

*   Deploy the Sigma rule `Detect Auditpol ResourceSACL Clearing` to your SIEM to detect the use of `auditpol.exe` to clear the `/resourceSACL` policy.
*   Enable process creation logging, specifically Windows Event ID 4688 or Sysmon Event ID 1, to capture command-line arguments of `auditpol.exe`.
*   Investigate any instances of `auditpol.exe` executions with the `/resourceSACL` flag and `/clear` or `/remove` arguments, as they could indicate malicious activity.
*   Implement the provided RBA (Risk Based Alerting) to prioritize alerts based on user and endpoint risk scores associated with the clearing of global object access audit policies.
