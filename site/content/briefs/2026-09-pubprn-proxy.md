---
title: Pubprn.vbs Proxy Execution via LOLBAS
slug: 2026-09-pubprn-proxy
description: Threat actors leverage the legitimate Microsoft signed script 'Pubprn.vbs' to proxy the execution of arbitrary scripts and evade security controls.
date: "2026-09-01T11:06:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1216
    technique_name: System Binary Proxy Execution
    evidence: The script is leveraged as a proxy to execute arbitrary code, bypassing security controls.
    confidence_band: high
references:
  - https://lolbas-project.github.io/lolbas/Scripts/Pubprn/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_lolbin_pubprn.yml
rules:
  - title: Detect Pubprn.vbs Proxy Execution
    description: Detects the use of the Microsoft signed script Pubprn.vbs to proxy the execution of remote or local scripts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1216.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect pubprn.vbs misuse.
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in brief.
  mitigation_plan:
    - priority: medium_term
      action: Implement script block logging and AppLocker/WDAC policies to restrict execution of untrusted scripts.
      owner: IT Operations
      addresses: T1216.001
      evidence: General best practices for script proxy evasion.
---

'Pubprn.vbs' is a built-in, digitally signed Windows script located in the System32 directory, intended for printer administration. Threat actors abuse this living-off-the-land binary (LOLBAS) to bypass application control policies and execution restrictions. By invoking the script with specific arguments, an attacker can point the script to a remote or local malicious .sct (Script Component) file, causing 'Pubprn.vbs' to load and execute the code within that file. Because 'Pubprn.vbs' is a trusted, signed Microsoft component, its usage to launch malicious payloads can often bypass signature-based detection mechanisms that rely on process reputation. Defenders must monitor for command-line arguments that utilize 'Pubprn.vbs' to load external scripts, as this is a known technique for proxying execution and maintaining stealth during the post-exploitation phase.

## Impact

Successful exploitation allows attackers to execute arbitrary code with the privileges of the user running the script. This facilitates defense evasion, persistence, and potential escalation if the script is invoked by a process with elevated permissions. This technique is observed in various campaigns involving fileless malware, credential harvesting, and staged payload delivery.

## Recommendation

* Deploy the provided Sigma rule to detect the specific command-line usage of 'Pubprn.vbs' for proxy execution.
* Establish a baseline for legitimate printer management activities in your environment to minimize false positives related to administrative scripts.
* Utilize EDR telemetry to audit all child processes spawned by 'cscript.exe' or 'wscript.exe' when 'Pubprn.vbs' is present in the parent process path.
