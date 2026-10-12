---
title: Detecting Malicious DLL Loading via Regsvr32
slug: 2026-10-regsvr32-dll-loading
description: Adversaries, including operators of Remcos and njRAT, utilize the Regsvr32 utility with silent and install parameters to load malicious DLLs for code execution and persistence.
date: "2026-10-12T17:55:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - defense-evasion
  - windows
  - rat
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: This activity is significant as it is commonly used by RAT malware like Remcos and njRAT to load malicious DLLs on compromised machines.
    confidence_band: high
references:
  - https://app.any.run/tasks/dc93ee63-050c-4ff8-b07e-8277af9ab939/
  - https://attack.mitre.org/techniques/T1218/010/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1218.010/T1218.010.yaml#L133
rules:
  - title: Detect Regsvr32 Silent and Install Param DLL Loading
    description: Detects the loading of a DLL using the regsvr32 application with the silent (/s) and DLLInstall (/i) parameters, a technique used by RAT malware to execute code.
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
    - action: Deploy the Sigma detection rule to monitor for Regsvr32 execution patterns.
      owner: Detection Engineering
      due: 48h
      evidence: Source explicitly identifies the regsvr32 /s /i pattern as a TTP for RAT malware.
  hunt_leads:
    - lead: Search historical logs for regsvr32 executions containing both silent and install flags.
      technique_id: T1218.010
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Documentation suggests common usage by RATs like Remcos and njRAT.
---

The Regsvr32 utility is a legitimate Windows command-line tool used to register and unregister OLE controls such as DLLs. Attackers frequently abuse this binary to execute arbitrary code by loading malicious DLLs while attempting to evade security monitoring. By executing Regsvr32 with the "/s" (silent) and "/i" (DLLInstall) flags, attackers can trigger the DllInstall export function within a target library, often bypassing traditional execution preventions or process monitoring that looks for direct execution of malicious binaries.

This technique is observed in the wild within the activity of various Remote Access Trojans (RATs), specifically Remcos and njRAT. Because the utility is a signed Microsoft binary, attackers leverage it as a Living-off-the-Land (LotL) technique. Detection engineers should focus on command-line telemetry that captures the simultaneous use of these specific flags. While legitimate software, such as Microsoft Teams, may occasionally invoke Regsvr32 with these parameters for registration tasks, identifying anomalous parent processes or unexpected execution paths is critical for high-fidelity alerting.

## Impact

Successful exploitation allows for stealthy execution of malicious code, leading to system compromise, data exfiltration, or the deployment of secondary payloads. By maintaining persistence through the registration of malicious DLLs, threat actors can ensure long-term access to the host, facilitating continued operations and potential data destruction or exfiltration across the organization's network.

## Recommendation

* Deploy the Sigma rule below to detect Regsvr32 executions containing both silent and install parameters, ensuring exclusion filters for known legitimate processes like Microsoft Teams are applied.
* Enable comprehensive process creation logging (e.g., Sysmon Event ID 1 or Windows Event ID 4688) to ensure command-line arguments are captured, as this is essential for identifying this technique.
* Use the provided detection logic to alert on Regsvr32 activity where the command line includes both "/s" and "/i" or "/i" and "/s".
* Investigate the parent process of any Regsvr32 execution identified by the alert to determine if it originated from a typical user application or a suspicious process like a web browser, script host, or office application.
