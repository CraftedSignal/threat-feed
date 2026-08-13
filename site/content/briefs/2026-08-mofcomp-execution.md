---
title: Suspicious Mofcomp Utility Execution
slug: 2026-08-mofcomp-execution
description: Detection logic for the abuse of the Windows mofcomp utility, which is frequently leveraged by attackers to compile malicious Managed Object Format (MOF) files for WMI event subscription persistence.
date: "2026-08-13T10:33:29Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The mofcomp utility is abused to install malicious MOF scripts.
    confidence_band: high
references:
  - https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
  - https://learn.microsoft.com/en-us/windows/win32/wmisdk/mofcomp
rules:
  - title: Potentially Suspicious Mofcomp Execution
    description: Detects execution of mofcomp.exe as a child of shell/script interpreters or from suspicious working directories.
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for mofcomp process creation.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific process and path artifacts.
  hunt_leads:
    - lead: Search for historical process creation events involving mofcomp.exe from non-standard system directories.
      technique_id: T1218
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source identifies mofcomp as a common abuse vector.
---

The mofcomp.exe utility is a native Windows component responsible for parsing Managed Object Format (MOF) files and integrating them into the WMI repository. Attackers abuse this utility to establish persistence or facilitate privilege escalation by registering malicious WMI event consumers. When executed from suspicious locations (such as temporary directories) or spawned by common shell and scripting interpreters (cmd.exe, powershell.exe, wscript.exe), mofcomp execution often indicates an attempt to subvert system monitoring or maintain backdoors. This brief provides detection engineering guidance to monitor for these patterns while filtering out legitimate administrative activity, such as legitimate WMI repository maintenance performed by SCCM or system services.

## Attack Chain

1. Attacker establishes initial access via spearphishing or exploit.
2. Attacker downloads a malicious MOF file to a user-writable directory (e.g., %TEMP% or C:\Users\Public).
3. Attacker executes a staging script or shell (e.g., cmd.exe or powershell.exe) to initiate the payload.
4. The script calls 'mofcomp.exe' pointing to the malicious MOF file located in a staging directory.
5. The mofcomp utility parses the file and registers the malicious WMI event consumer in the CIM repository.
6. The WMI event subscription triggers the malicious payload upon a system event (e.g., system startup or specific time interval).
7. Final objective is achieved: persistent, elevated execution of arbitrary code via WMI service.

## Impact

Successful abuse of mofcomp allows attackers to maintain persistence that survives system reboots and often bypasses basic file-based security controls by executing code within the context of the WMI service. This technique is commonly associated with cryptominers, remote access trojans (RATs), and various persistence mechanisms across enterprise environments.

## Recommendation

Deploy the provided Sigma rule to monitor process creation events for suspicious mofcomp.exe invocations. Ensure Sysmon or native Windows process auditing (Event ID 4688 with command-line auditing enabled) is active. Filter out known administrative workflows, such as Configuration Manager components, to reduce noise. Investigate any alerts originating from unexpected parent processes or unauthorized paths.
