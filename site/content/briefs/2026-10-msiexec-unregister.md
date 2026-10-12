---
title: Abuse of MSIExec for DLL Unregistration
slug: 2026-10-msiexec-unregister
description: Adversaries abuse the msiexec.exe /z parameter to unregister DLLs, facilitating defense evasion and disruption of security controls.
date: "2026-10-12T18:16:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - masquerading
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The following analytic detects the use of msiexec.exe with the /z switch parameter, which is used to unload DLLRegisterServer.
    confidence_band: high
references:
  - https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md
rules:
  - title: Detect MSIExec Unregister DLLRegisterServer
    description: Detects the use of msiexec.exe with the /z parameter to unload DLLRegisterServer, often used for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1218.007
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
    - action: Deploy the MSIExec /z detection rule to the SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides explicit analytic logic for this behavior.
  hunt_leads:
    - lead: Search for historical execution of msiexec.exe with /z flags in process logs.
      technique_id: T1218.007
      data_needed:
        - Endpoint process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This activity is indicative of tampering.
---

The Windows Installer utility, msiexec.exe, is frequently abused by attackers to perform unauthorized operations on system DLLs. Specifically, the use of the /z command-line switch instructs msiexec to invoke the DLLRegisterServer function in a specified DLL to unregister it. This technique allows adversaries to disable security products, bypass monitoring hooks, or disrupt system functionality to evade detection. This behavior is often observed in the later stages of an attack chain where the adversary seeks to maintain persistence or mask subsequent malicious activity. Defenders should monitor for instances of msiexec.exe executing with the /z parameter, as it rarely appears in legitimate administrative workflows and is a high-fidelity indicator of malicious intent or tampering.

## Attack Chain

1. Initial access is established via phishing or exploitation, granting the attacker a foothold on the target endpoint.
2. The attacker performs local reconnaissance to identify security products or monitoring agents residing on the system.
3. The attacker locates the DLLs associated with security products or auditing hooks.
4. The attacker executes msiexec.exe with the /z switch, targeting the identified security DLLs to trigger the unregistration process.
5. The unregistration of the DLL effectively disables the targeted security control or monitoring agent.
6. The adversary proceeds to perform primary objectives, such as data exfiltration or credential theft, with reduced risk of detection.

## Impact

Successful abuse of this technique allows an attacker to blind security operations by disabling endpoint detection and response (EDR) modules or other security logging utilities. This can lead to total loss of visibility on the host, enabling long-term persistence and unauthorized access to sensitive data across the organization's network.

## Recommendation

* Deploy the provided Sigma rule to detect the execution of msiexec.exe with the /z parameter.
* Enable Sysmon Event ID 1 or Windows Event ID 4688 to capture comprehensive process creation command-line arguments.
* Establish a baseline of legitimate msiexec.exe activity in the environment to tune the detection and eliminate false positives caused by authorized software maintenance tools.
