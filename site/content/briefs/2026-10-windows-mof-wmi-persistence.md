---
title: Detecting WMI Event Subscription Persistence via MOFComp
slug: 2026-10-windows-mof-wmi-persistence
description: Attackers utilize the MOFComp utility to compile Managed Object Format (MOF) files for establishing WMI event subscriptions, enabling persistence, lateral movement, or arbitrary code execution on Windows systems.
date: "2026-10-12T18:14:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - lateral-movement
  - execution
  - wmi
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: This activity is significant as it may indicate an attacker using WMI for persistence or lateral movement.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1546/003/
  - https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
  - https://docs.microsoft.com/en-us/windows/win32/wmisdk/mofcomp
  - https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/
rules:
  - title: Detect MOFComp Execution from Suspicious Paths or Parents
    description: Detects the execution of mofcomp.exe when triggered by command-line shells or running from suspicious user-writable directories, which may indicate WMI persistence installation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the MOFComp detection rule and tune for administrative automation.
      owner: Detection Engineering
      due: 48h
      evidence: Source emphasizes the need for monitoring and filtering of administrative tools.
  hunt_leads:
    - lead: Search for historical process creation events of mofcomp.exe from non-standard system paths.
      technique_id: T1546.003
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: MOFComp execution from User Profile directories is an indicator of malicious activity.
  mitigation_plan:
    - priority: medium
      action: Implement application allowlisting or constrained execution policies for mofcomp.exe.
      owner: IT Operations
      addresses: T1546.003
      evidence: Execution of mofcomp.exe is a known persistence vector.
---

The MOFComp (Managed Object Format Compiler) utility is a legitimate Windows component designed to parse MOF files and add their contents to the WMI repository. Threat actors frequently abuse this utility to install malicious WMI event subscriptions, which trigger arbitrary code execution upon specific system events. This technique allows for stealthy persistence and can be used for lateral movement. 

Defenders should monitor for the execution of 'mofcomp.exe' when spawned by unusual parent processes such as 'cmd.exe' or 'powershell.exe', or when the binary is executed from non-standard locations such as user-writable directories (e.g., AppData, Public folders). This activity is a known indicator of post-exploitation behavior where an attacker has already gained code execution and is attempting to embed themselves into the host system's management infrastructure.

## Attack Chain

1. Initial access is established on the Windows host via spearphishing, exploit, or credential theft.
2. The attacker drops a malicious MOF file onto the target system, often in a directory like 'C:\Users\Public\' or a user's 'AppData\Local\' folder.
3. The attacker initiates the compilation of the malicious MOF file using the 'mofcomp.exe' binary.
4. The command execution is often wrapped in a script (CMD or PowerShell) to mask the activity or automate the process.
5. The MOF file instructs the WMI repository to create a new '__EventFilter' or 'ActiveScriptEventConsumer' that points to the attacker's payload.
6. The WMI system confirms the registration of the new event subscription.
7. Upon the defined system trigger (e.g., system uptime, user logon), the WMI Event Consumer executes the malicious payload with elevated privileges.
8. The attacker achieves persistent, automatic code execution on the compromised host.

## Impact

Successful exploitation allows for long-term persistence within an environment, enabling attackers to maintain access even after system reboots. This can facilitate continued exfiltration of data, credential harvesting, and command-and-control communication, potentially leading to full system compromise and lateral movement within the network.

## Recommendation

- Implement monitoring for 'mofcomp.exe' process creation events (Sysmon Event ID 1 or Windows Event 4688).
- Prioritize alerts where 'mofcomp.exe' is spawned by 'cmd.exe' or 'powershell.exe'.
- Flag any 'mofcomp.exe' execution originating from 'AppData\Local\' or 'C:\Users\Public\' paths.
- Tune the detection logic for legitimate automation and management tools like SCCM that may legitimately use MOFComp.
- Review the Atomic Red Team test T1546.003 to validate detection coverage in your environment.
