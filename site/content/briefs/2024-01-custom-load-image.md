---
title: CustomLoadImage .NET Assembly Loading Technique
slug: 2024-01-custom-load-image
description: CustomLoadImage enables stealthy reflective loading of .NET assemblies by directly calling AssemblyNative::LoadFromBuffer, bypassing hooks on RuntimeAssembly.nLoadImage for defense evasion.
date: "2024-01-09T16:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - .net
  - reflective-loading
vendors:
  - Microsoft
products:
  - .NET Framework
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://www.reddit.com/r/blueteamsec/comments/1s1pf8f/customloadimage/
  - https://github.com/backdoorskid/CustomLoadImage
iocs:
  - type: url
    value: https://github.com/backdoorskid/CustomLoadImage
ioc_counts:
  url: 1
rules:
  - title: Detect AssemblyNative::LoadFromBuffer Call
    description: Detects calls to AssemblyNative::LoadFromBuffer, which is used by CustomLoadImage to bypass normal assembly loading procedures.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Detect .NET Assembly Loaded From Memory
    description: Detects .NET assemblies loaded from memory, potentially indicating reflective loading techniques like CustomLoadImage.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - image_load
      - windows
rules_count: 2
---

The CustomLoadImage technique allows threat actors to bypass traditional security measures when loading .NET assemblies. By directly invoking the `AssemblyNative::LoadFromBuffer` function, it circumvents hooks that security products often place on `RuntimeAssembly.nLoadImage`. This direct invocation provides a stealthier method for loading malicious .NET assemblies into memory. This technique is relevant because it allows attackers to evade common detection strategies and execute malicious .NET code without triggering alerts based on standard assembly loading procedures. The tool is available on GitHub at the provided URL.

## Attack Chain

1.  Attacker gains initial access to the target system (e.g., through phishing or exploiting a vulnerability).
2.  Attacker deploys a custom loader, implementing the CustomLoadImage technique, onto the target system.
3.  The custom loader uses `AssemblyNative::LoadFromBuffer` to load a malicious .NET assembly directly into memory.
4.  This bypasses any hooks or checks that might be placed on `RuntimeAssembly.nLoadImage`.
5.  The malicious .NET assembly executes its intended payload within the compromised process.
6.  The payload may perform actions like credential theft, lateral movement, or data exfiltration.
7.  The attacker maintains persistence, potentially by scheduling the malicious .NET assembly to reload using CustomLoadImage after system restarts.

## Impact

Successful exploitation of the CustomLoadImage technique allows attackers to execute arbitrary .NET code on a compromised system while evading common security defenses. This can lead to a variety of malicious outcomes, including data theft, system compromise, and further propagation within the network. The stealthy nature of this technique makes it harder to detect and remediate, increasing the potential for significant damage.

## Recommendation

*   Monitor process memory for the execution of .NET assemblies loaded from unusual locations or without corresponding file paths; investigate any anomalies (Generic detection capability).
*   Implement endpoint detection rules that flag processes calling `AssemblyNative::LoadFromBuffer` directly, especially when originating from non-standard or untrusted processes (see Sigma rule examples below).
*   Inspect network traffic for unusual data patterns that may indicate exfiltration initiated by reflectively loaded assemblies.
