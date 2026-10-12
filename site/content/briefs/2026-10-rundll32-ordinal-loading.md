---
title: Detection of Rundll32 Execution via DLL Ordinals
slug: 2026-10-rundll32-ordinal-loading
description: Adversaries leverage the rundll32.exe utility to execute malicious DLL export functions by ordinal value, a technique designed to evade standard process monitoring and security controls.
date: "2026-10-12T17:56:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
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
    evidence: The following analytic detects rundll32.exe loading a DLL export function by ordinal value.
    confidence_band: high
references:
  - https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1218.011/T1218.011.yaml#L222
rules:
  - title: Detect Rundll32 Loading DLL By Ordinal
    description: Detects rundll32.exe loading a DLL export function by ordinal value by monitoring process command-line arguments.
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
    - action: Deploy Sigma detection for rundll32.exe ordinal execution.
      owner: Detection Engineering
      due: 48h
      evidence: Source detection logic.
  hunt_leads:
    - lead: Search for historical rundll32 command lines containing '#' symbols.
      technique_id: T1218.011
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Adversary usage of ordinals in rundll32.exe is a known TTP.
---

Adversaries frequently utilize the native Windows utility rundll32.exe to execute arbitrary code. A specific technique involves calling an exported function within a DLL by its ordinal number rather than its name. This method is effective for evasion because many security tools and analysts focus on function names when performing static analysis or monitoring command-line arguments. By referencing the ordinal (e.g., rundll32.exe some.dll,#1), the attacker can successfully load and execute malicious payloads while remaining inconspicuous. This behavior has been observed in various campaigns, including those involving the IcedID malware. Defending against this requires deep visibility into process execution and command-line telemetry to identify suspicious patterns of rundll32.exe usage.

## Impact

Successful execution of this technique allows for arbitrary code execution, which can lead to full system compromise, privilege escalation, or the establishment of persistent access. This is a common TTP observed across numerous threat actor campaigns targeting Windows environments for malware deployment and post-exploitation activity.

## Recommendation

Detection engineering teams should focus on identifying process creation events where rundll32.exe command lines contain ordinal references.

* Deploy the provided Sigma rule to capture rundll32.exe processes containing the '#' character followed by digits in the command line.
* Enable Sysmon Event ID 1 or Windows Event Log Security 4688 to ensure full command-line visibility.
* Tune the detection by filtering against known-good binaries or third-party applications that legitimately utilize ordinal exports for compatibility.
