---
title: Abuse of Regsvr32 for Application Control Bypass
slug: 2026-10-regsvr32-bypass
description: Attackers abuse the trusted Microsoft Regsvr32 utility to proxy malicious code execution via 'scrobj.dll', a technique commonly known as 'Squiblydoo' used to bypass application control.
date: "2026-10-12T17:41:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - living-off-the-land
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events and command-line executions.
    confidence_band: high
rules:
  - title: Detect Regsvr32 Application Control Bypass
    description: Detects the abuse of Regsvr32.exe to proxy execution of malicious code, specifically by loading 'scrobj.dll'.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.010
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to identify Regsvr32/scrobj.dll abuse.
      owner: Detection Engineering
      due: 24h
      evidence: Analytic description confirms this is a high-fidelity indicator.
  hunt_leads:
    - lead: Search for regsvr32.exe processes with command lines containing remote URL patterns or .sct extensions.
      technique_id: T1218.010
      data_needed:
        - Process creation events with command-line arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The technique is a known mechanism for application control bypass.
  mitigation_plan:
    - priority: short_term
      action: Configure AppLocker or WDAC to enforce strict rules for script-hosting binaries.
      owner: IT Operations
      addresses: T1218.010
      evidence: Microsoft security support documentation.
---

Regsvr32.exe is a command-line utility used to register and unregister OLE controls, such as DLLs, in the Windows Registry. Because it is a signed, trusted Microsoft binary, it is frequently abused by threat actors to proxy the execution of arbitrary malicious code, effectively bypassing application control mechanisms such as AppLocker or Windows Defender Application Control (WDAC). This technique, often referred to as "Squiblydoo," involves using Regsvr32.exe to load a remote or local script file via the "scrobj.dll" component. By executing scripts through this legitimate binary, attackers can achieve code execution and establish persistent access while remaining hidden from signature-based security controls. This activity has been observed in various campaigns, including ransomware operations and Cobalt Strike deployments. Defenders must monitor process creation and command-line arguments to detect the loading of scrobj.dll by regsvr32.exe, as this is a high-fidelity indicator of malicious intent.

## Attack Chain

1. Attacker gains initial access to the Windows host through a spearphishing email or exploitation of a service.
2. Attacker writes a malicious script (.sct file) to a local directory or identifies a remote URL hosting the script.
3. Attacker executes `regsvr32.exe` from a command prompt or terminal.
4. The `regsvr32.exe` process is invoked with command-line arguments specifying the "/s" (silent) flag.
5. The attacker includes the "/i" flag followed by the path or URL of the malicious .sct file.
6. `regsvr32.exe` loads `scrobj.dll` to parse and execute the script content within the context of the trusted process.
7. The malicious script executes its payload, such as a shellcode stager or backdoor.
8. The attacker achieves code execution, persistence, or begins lateral movement within the environment.

## Impact

Successful exploitation of this technique allows attackers to bypass application control policies, enabling the execution of unauthorized or malicious code. This can lead to full system compromise, exfiltration of sensitive data, deployment of ransomware, or the establishment of long-term persistence in the target environment. The use of a trusted system binary makes this activity difficult to detect without specific telemetry focused on process behavior and command-line arguments.

## Recommendation

1. Deploy the Sigma rules below to your SIEM to monitor for suspicious invocations of regsvr32.exe.
2. Ensure that process creation events (specifically Sysmon Event ID 1) are being ingested and that command-line arguments are captured in full.
3. Implement AppLocker or WDAC policies that explicitly restrict the execution of untrusted scripts or the use of Regsvr32 in a manner consistent with script loading.
4. Use the provided process creation telemetry to alert on regsvr32.exe command lines containing "scrobj.dll" or ".sct" files.
