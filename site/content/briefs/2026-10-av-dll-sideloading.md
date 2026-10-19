---
title: Detection of DLL Sideloading Targeting Antivirus Software
slug: 2026-10-av-dll-sideloading
description: This brief provides detection logic for identifying potential DLL sideloading attempts that leverage legitimate antivirus software components to achieve persistence or privilege escalation.
date: "2026-10-19T09:50:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - stealth
  - windows
  - dll-sideloading
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574.001
    technique_name: DLL Search Order Hijacking
    evidence: The technique utilizes DLL sideloading to execute malicious code within trusted application contexts.
    confidence_band: high
rules:
  - title: Potential Antivirus Software DLL Sideloading
    description: Detects potential DLL sideloading of DLLs that are part of antivirus software such as McAfee, Symantec, ESET, etc. The rule filters out known legitimate paths for these libraries.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1574.001
    data_sources:
      - image_load
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule for detection of sideloaded antivirus DLLs.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides community-vetted detection logic for this TTP.
  hunt_leads:
    - lead: Search for instances of antivirus-related DLLs loading from non-standard vendor directories.
      technique_id: T1574.001
      data_needed:
        - Sysmon Event ID 7
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Sideloading typically manifests in unauthorized directory loads.
---

DLL sideloading remains a persistent technique used by adversaries to execute malicious code within the context of trusted applications. By placing a malicious DLL with the same name as a legitimate library expected by an application, attackers can force the application to load the malicious file, often leading to code execution with the permissions of the host process. This intelligence focuses on the abuse of common DLLs associated with widely deployed antivirus and endpoint protection suites, such as McAfee, Avast, ESET, and CyberArk. Because these applications are often trusted by security policy and possess high system privileges, they are prime targets for sideloading to gain stealthy persistence or elevate privileges. Defenders should monitor image load events to identify instances where these specific DLLs are loaded from unauthorized directories.

## Attack Chain

1. Attacker performs reconnaissance to identify vulnerable applications on the target host.
2. Attacker obtains the file path of a legitimate application that relies on specific DLLs.
3. Attacker crafts a malicious DLL that exports the same functions as the target legitimate library.
4. Attacker writes the malicious DLL to a directory where the target application will search for it, or overwrites an existing DLL.
5. Attacker executes the target legitimate application process (e.g., an antivirus service or binary).
6. The target application initiates an image load request and resolves the malicious DLL instead of the legitimate one.
7. The operating system loads the malicious code into the process memory, executing the attacker payload with elevated process privileges.

## Impact

Successful exploitation allows for stealthy execution of malicious code, potential bypassing of endpoint security controls, privilege escalation, and persistent access to the compromised host.

## Recommendation

* Deploy the provided Sigma rule for `image_load` event monitoring to detect unauthorized loading of antivirus-related DLLs.
* Establish a baseline of legitimate paths for these specific DLLs and tune the detection to exclude valid vendor directories.
* Investigate processes that load these DLLs from locations outside of standard `C:\Program Files\` or `C:\Program Files (x86)\` subdirectories.
* Enable EDR/Sysmon telemetry specifically for `ImageLoaded` events (Event ID 7 in Sysmon) to ensure visibility into library loading patterns.
