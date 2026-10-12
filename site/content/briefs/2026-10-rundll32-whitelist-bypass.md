---
title: Windows Application Whitelisting Bypass via Rundll32
slug: 2026-10-rundll32-whitelist-bypass
description: Attackers can bypass application whitelisting policies by leveraging rundll32.exe to execute arbitrary code through specific Windows library functions, facilitating persistence and privilege escalation.
date: "2026-10-12T18:01:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - lotl
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: This method is identified through Endpoint Detection and Response (EDR) telemetry, focusing on command-line executions and process details.
    confidence_band: high
rules:
  - title: Detect Windows Application Whitelisting Bypass via Rundll32
    description: Detects the execution of rundll32.exe loading specific DLLs and calling functions often used for application whitelisting bypass.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.011
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma detection rule to environment
      owner: Detection Engineering
      due: 48h
      evidence: Source provides vetted detection search logic
  hunt_leads:
    - lead: Search for historical execution of rundll32.exe with INF-related function calls
      technique_id: T1218.011
      data_needed:
        - Process creation events with command-line arguments
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Technique is frequently used by attackers to bypass security controls
  mitigation_plan:
    - priority: medium
      action: Implement strict application control policies that restrict the execution of unsigned or non-standard INF files
      owner: IT Operations
      addresses: T1218.011
      evidence: Source identifies this as an application whitelisting bypass technique
---

The rundll32.exe binary is a legitimate Windows system utility designed to run DLL-based programs. Threat actors frequently abuse this binary as a Living Off the Land (LotL) technique to bypass application whitelisting and execute arbitrary code. By invoking specific exported functions - namely "LaunchINFSection", "InstallHinfSection", or "SetupInfObjectInstallAction" - within libraries like Advpack.dll, Ieadvpack.dll, Syssetup.dll, or Setupapi.dll, an attacker can trigger the execution of script-based content contained within INF files. This activity is critical for detection engineers to monitor, as it often precedes more damaging actions such as secondary payload download, privilege escalation, or establishing persistence on a compromised Windows host. The technique is well-documented in the LOLBAS project and leveraged in various red team exercises to bypass security controls.

## Impact

Successful exploitation allows attackers to execute arbitrary code under the context of the rundll32.exe process, potentially bypassing application control solutions. This can lead to full system compromise, including privilege escalation, sensitive data exfiltration, or the deployment of secondary malware. While the specific number of victims varies, this technique is a core component of many advanced persistent threat (APT) toolsets that target enterprise environments running Windows.

## Recommendation

Detection engineering teams should prioritize visibility into process execution command lines to identify the use of the specified DLLs and function exports.

* Deploy the provided Sigma rule to detect suspicious rundll32 command-line arguments.
* Enable Sysmon Event ID 1 (Process Creation) or Windows Event ID 4688 to capture full command-line strings for monitoring.
* Establish a baseline of legitimate software (such as specialized DLP agents) that might utilize these DLLs to prevent false positives in the detection logic.
* Regularly audit systems for unexpected parent-child process relationships involving rundll32.exe.
