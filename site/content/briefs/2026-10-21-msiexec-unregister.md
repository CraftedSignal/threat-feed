---
brief_id: brief-2026-10-21-msiexec-unregister
event_id: brief-2026-10-21-msiexec-unregister
revision: 1
activity_at: "2026-10-21T00:48:22Z"
title: MsiExec DllUnregisterServer execution
slug: 2026-10-21-msiexec-unregister
description: Adversaries may abuse the legitimate msiexec.exe binary to execute arbitrary code contained within a DLL by invoking the DllUnregisterServer function.
date: "2026-10-21T00:48:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - windows
  - living-off-the-land
  - stealth
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    subtechnique_id: T1218.007
    subtechnique_name: Msiexec
    evidence: Adversaries may abuse the legitimate msiexec.exe binary to execute arbitrary code contained within a DLL by invoking the DllUnregisterServer function.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_msiexec_dll.yml
  - https://lolbas-project.github.io/lolbas/Binaries/Msiexec/
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md
rules:
  - title: Detect DllUnregisterServer execution via MsiExec
    description: Detects MsiExec loading a DLL and calling its DllUnregisterServer function using the /Z flag
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect anomalous msiexec /z usage
      owner: Detection Engineering
      due: 48h
      evidence: Source provides detection logic for this TTP
  hunt_leads:
    - lead: Search for process creation events of msiexec.exe with /z and .dll in the command line
      technique_id: T1218.007
      data_needed:
        - process_creation
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies this as a mechanism for executing code via msiexec
---

The Windows Installer utility (msiexec.exe) is a signed, legitimate binary used for installing and configuring software. Attackers can leverage the "/Z" flag to load a specified DLL and call its exported "DllUnregisterServer" function. This technique is often used to bypass security controls or execute malicious code in the context of a trusted process. Because this behavior is atypical for standard administrative tasks outside of specific update or maintenance workflows, it serves as a high-fidelity indicator of potential malicious activity. Defenders should monitor process command lines for the use of the "/Z" parameter in conjunction with external DLL references.

## Attack Chain

1. Attacker crafts a malicious DLL file containing a payload within the DllUnregisterServer exported function.
2. The DLL is staged on the target system, typically in a directory where the user or service has write permissions.
3. Attacker identifies the msiexec.exe utility, a native Windows component.
4. Attacker executes msiexec.exe via command line using the "/Z" flag.
5. The command line specifies the full path to the malicious DLL as the argument for the "/Z" parameter.
6. MsiExec initializes and loads the attacker-supplied DLL into its memory space.
7. MsiExec calls the DllUnregisterServer function within the loaded DLL.
8. The payload executes, potentially resulting in secondary malware deployment, C2 communication, or lateral movement.

## Impact

Successful exploitation allows for execution of arbitrary code in the context of the msiexec.exe process, potentially bypassing application allowlisting and leveraging the trusted reputation of the Windows Installer binary.

## Recommendation

Deploy the provided Sigma rule to detect suspicious msiexec.exe invocations. Audit legitimate software installers or update agents in the environment that may utilize the "/Z" flag and include them in the filter logic of the detection rule.
