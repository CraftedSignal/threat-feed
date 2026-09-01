---
title: Suspicious Dynamic .NET Compilation via Csc.exe
slug: 2026-09-dynamic-dotnet-compilation
description: Attackers utilize the C# compiler (csc.exe) to dynamically compile and execute malicious code in memory, enabling evasion of signature-based defenses and EDR hooks.
date: "2026-09-01T12:19:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - evading-security-controls
  - windows
  - dot-net
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: Attackers often leverage this to compile code on the fly and use it in other stages.
    confidence_band: high
rules:
  - title: Detect Suspicious Dynamic .NET Compilation via Csc.exe
    description: Detects execution of csc.exe from suspicious or user-writable locations commonly used by attackers to compile payloads on the fly.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1027.004
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in official Sigma repository.
  hunt_leads:
    - lead: Search for csc.exe executions in non-system directories
      technique_id: T1027.004
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies csc.exe abuse patterns.
---

The C# compiler (csc.exe) is a legitimate component of the .NET framework used for building source code into assemblies. Threat actors, including groups observed in MuddyWater operations and campaigns utilizing Agent Tesla, abuse this utility to perform dynamic, on-the-fly compilation of malicious payloads. By compiling code directly on the target host, attackers avoid writing static malicious binaries to disk, thereby bypassing traditional file-based signature detection. This technique is often employed in the post-exploitation phase to execute custom loaders, stagers, or modules that interact with system APIs to disable security instrumentation or perform further reconnaissance. Defenders should monitor for csc.exe process creation events occurring within non-standard execution paths, such as temporary user directories or user-profile subfolders, which are common staging areas for this activity.

## Attack Chain

1. Initial access is established via phishing or exploit, placing a source code file (typically .cs) on the host.
2. Attacker writes the malicious source code to a temp location, such as C:\Users\Public\ or %TEMP%.
3. Attacker invokes csc.exe from the command line to compile the written source code.
4. The compiler (csc.exe) reads the source file and generates an assembly in memory or as a temporary executable.
5. The resulting assembly is executed, either directly through process injection or via a follow-on execution command.
6. The malicious assembly executes, performing tasks like API hooking removal or C2 beaconing.
7. The primary objective, such as credential theft or sensitive data exfiltration, is achieved using the memory-resident code.

## Impact

Successful abuse of dynamic compilation allows attackers to execute arbitrary code while significantly reducing their disk footprint. This technique has been observed in global operations targeting varied sectors, allowing actors to maintain persistence and evade endpoint security controls. Failure to detect this activity can lead to long-term undetected presence within a network, resulting in unauthorized data access and potential system compromise.

## Recommendation

1. Deploy the provided Sigma rule to detect suspicious csc.exe execution patterns.
2. Baseline legitimate csc.exe usage in the environment, specifically identifying build pipelines or automated tools that invoke the compiler from standard directories (e.g., C:\Program Files\).
3. Implement process creation logging via Sysmon (Event ID 1) to capture command line arguments and parent process relationships for csc.exe.
4. Hunt for anomalous process execution paths for csc.exe (e.g., AppData, Temp, Perflogs) and correlate these events with unexpected network activity or unauthorized API calls.
