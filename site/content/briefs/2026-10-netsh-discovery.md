---
title: Detection of Netsh Network Configuration Discovery
slug: 2026-10-netsh-discovery
description: Adversaries utilize the Windows native 'netsh.exe' utility to perform reconnaissance on firewall rules and network configurations to facilitate post-exploitation activities and security control bypass.
date: "2026-10-12T18:24:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - post-exploitation
  - windows
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Connections Discovery
    evidence: The following analytic detects the execution of the Windows built-in tool netsh.exe to display the state, configuration, and profile of the host firewall.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1049/
  - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
  - https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/
rules:
  - title: Detect Netsh Network Configuration Discovery
    description: Detects the use of netsh.exe to display firewall or network configurations, which is a common technique for environmental reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1049
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to the SIEM.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides analytic content.
---

The Windows utility 'netsh.exe' is a command-line scripting utility that allows for the display and modification of network configurations. Threat actors frequently abuse this tool to perform discovery of firewall profiles, active rules, and adapter settings. This reconnaissance phase provides attackers with insights into the host's security posture, enabling them to identify paths for lateral movement or methods to disable security controls. This behavior has been observed in various post-exploitation toolkits, including winPEAS, and is frequently employed by ransomware families such as Prestige, as well as several information stealers like Snake Keylogger and BlankGrabber. Defenders should monitor for suspicious execution patterns of 'netsh' that involve queries for network state or firewall configurations, as these are rarely required by typical user activity.

## Attack Chain

1. Initial access is established on the Windows endpoint via phishing, exploit, or credential theft.
2. The attacker executes a discovery command to identify network and firewall configurations using 'netsh.exe'.
3. The attacker parses the command output to locate permissive firewall rules or active network segments.
4. Optionally, the attacker uses further 'netsh' commands to modify firewall rules or disable security features.
5. The attacker initiates lateral movement tools or scripts based on the collected environment data.
6. Data exfiltration or ransomware encryption is performed once the environment security controls are mitigated.

## Impact

Successful reconnaissance via 'netsh' often precedes unauthorized network access, data exfiltration, or the deployment of ransomware. By understanding the host firewall state, attackers significantly increase their success rate in establishing persistent, covert communication with command-and-control infrastructure.

## Recommendation

1. Deploy the provided Sigma rule to monitor for suspicious command-line patterns involving 'netsh.exe'.
2. Baseline the environment to identify legitimate administrative tools or scripts that utilize 'netsh' and create exclusion filters to reduce false positives.
3. Enable Sysmon Event ID 1 (Process Creation) with command-line auditing to ensure full visibility into the execution context of administrative binaries.
4. Prioritize investigation of alerts where 'netsh' is launched from unusual parent processes, such as PowerShell, command shells, or suspected web server worker processes.
