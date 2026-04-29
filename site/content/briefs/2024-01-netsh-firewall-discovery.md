---
title: Windows Netsh Tool Used for Firewall Discovery
slug: 2024-01-netsh-firewall-discovery
description: The analytic detects the execution of the Windows built-in tool netsh.exe to display the state, configuration, and profile of the host firewall, potentially leading to unauthorized network access or data exfiltration.
date: "2024-01-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - discovery
  - windows
  - netsh
  - firewall
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Connections Discovery
references:
  - https://attack.mitre.org/techniques/T1049/
  - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
  - https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/
rules:
  - title: Detect Suspicious Netsh Firewall Discovery
    description: Detects the execution of netsh.exe with commands to display firewall state, config, wlan, or profile.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1049
    data_sources:
      - process_creation
      - windows
  - title: Netsh Allowed Program Discovery
    description: Detects netsh being used to list the allowed programs in Windows Firewall.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1049
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on identifying instances where the `netsh.exe` utility is used to query firewall configurations on a Windows system. While `netsh.exe` is a legitimate tool for network configuration, adversaries can leverage it to gather information about firewall rules and settings. This information can then be used to plan further attacks, such as bypassing firewall restrictions or identifying vulnerable network services. This activity is typically seen during the reconnaissance phase of an attack. The scope of this detection covers any Windows environment where Endpoint Detection and Response (EDR) logs are available.

## Attack Chain

1. An attacker gains initial access to a compromised system through various means, such as phishing or exploiting a vulnerability.
2. The attacker executes `netsh.exe` with specific commands to enumerate firewall rules and configurations (e.g., `netsh firewall show state`, `netsh firewall show config`).
3. The `netsh.exe` process retrieves the requested firewall information from the Windows operating system.
4. The collected firewall information is parsed to identify potential weaknesses or misconfigurations.
5. The attacker uses the gathered information to modify existing firewall rules or create new rules to allow unauthorized access.
6. The attacker leverages the modified firewall configuration to establish a covert communication channel or to move laterally within the network.
7. The attacker attempts to exfiltrate sensitive data or deploy ransomware.

## Impact

Successful exploitation can lead to unauthorized network access, data exfiltration, or the deployment of ransomware. The enumeration of firewall configurations can provide attackers with valuable insights into the network's security posture, enabling them to bypass security controls and compromise critical assets. This can result in significant financial losses, reputational damage, and disruption of business operations.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious Netsh Firewall Discovery` to your SIEM and tune for your environment to detect netsh.exe executions with firewall discovery commands.
*   Enable Sysmon process-creation logging (Event ID 1) to capture the necessary command-line details.
*   Investigate any identified instances of `netsh.exe` being used to query firewall settings, especially when initiated from unusual processes or user accounts.
*   Monitor parent-child process relationships to identify suspicious process spawning, as highlighted by the `Processes.parent_process_name` field.
*   Review firewall configurations regularly to identify and remediate any misconfigurations or overly permissive rules.
