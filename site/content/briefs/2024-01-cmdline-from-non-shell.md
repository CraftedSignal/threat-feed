---
title: Windows Command-Line Tool Execution from Non-Shell Process
slug: 2024-01-cmdline-from-non-shell
description: Detection of command-line tools such as `ipconfig.exe` and `systeminfo.exe` being executed from non-standard parent processes can indicate system discovery activity by threat actors like FIN7 using injected processes.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - FIN7
  - Carbon Spider
  - Sangria Tempest
tags:
  - discovery
  - process-injection
  - fin7
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.mandiant.com/resources/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation
  - https://attack.mitre.org/groups/G0046/
  - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
rules:
  - title: Detect Cmdline Tool Execution From Non Shell Process
    description: Detects command-line tools executed from non-shell parent processes.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
  - title: Detect Cmdline Tool Execution From Non Shell Process Suspicious Path
    description: Detects command-line tools executed from non-shell parent processes with a suspicious path.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This analytic identifies instances where command-line tools such as `ipconfig.exe`, `systeminfo.exe`, `net1.exe`, `arp.exe`, `nslookup.exe`, `route.exe`, `netstat.exe`, `hostname.exe`, and `whoami.exe` are executed by a non-standard shell parent process, excluding `cmd.exe`, `powershell.exe`, `powershell_ise.exe`, `pwsh.exe`, and `explorer.exe`. This activity is often indicative of adversaries using injected processes to perform system discovery, as seen in FIN7's JSSLoader campaign. The JSSLoader malware, associated with FIN7, utilizes this technique to gather host information after initial compromise. This behavior is significant because it allows attackers to gather critical host information, which can be used for further exploitation or lateral movement within the network. The detection relies on Endpoint Detection and Response (EDR) telemetry to monitor process creation events.

## Attack Chain

1. Initial Access: The attacker gains initial access through unspecified means. (Observed in FIN7 campaigns but not detailed here.)
2. Process Injection: The attacker injects malicious code into a legitimate running process, such as explorer.exe or a third-party application.
3. Discovery: The injected process spawns command-line tools like `ipconfig.exe`, `systeminfo.exe`, `net1.exe`, `arp.exe`, `nslookup.exe`, `route.exe`, `netstat.exe`, `hostname.exe`, or `whoami.exe`.
4. System Reconnaissance: These tools are used to gather information about the compromised host, including IP configuration, system details, network statistics, and routing tables.
5. Data Collection: The attacker collects the output from these command-line tools.
6. Lateral Movement: The collected information is used to identify potential targets for lateral movement within the network.
7. Further Exploitation: Using the gathered information, the attacker exploits vulnerabilities or misconfigurations to gain access to additional systems.
8. Goal: The attacker aims to steal data, deploy ransomware, or achieve other malicious objectives.

## Impact

Successful exploitation can lead to the compromise of critical systems, data theft, and potential ransomware deployment. The observed activity is associated with FIN7, a financially motivated threat actor known for targeting various sectors. The compromise of systems can result in significant financial losses, reputational damage, and operational disruption. Multiple organizations have been affected by similar campaigns.

## Recommendation

*   Enable Sysmon process creation logging (Event ID 1) or Windows Event Log Security auditing (4688) to capture process GUID, process name, parent process, and command-line executions.
*   Deploy the Sigma rule `Detect Cmdline Tool Execution From Non Shell Process` to your SIEM to identify suspicious process execution patterns.
*   Investigate any instances of command-line tools being executed by unexpected parent processes as identified by the Sigma rule.
*   Monitor network connections originating from processes identified as anomalous by the Sigma rule, to identify potential C2 traffic.
*   Review historical process execution data to identify potential past compromises using this technique.
*   Use endpoint detection and response (EDR) systems to collect the process GUID, process name, and parent process information.
