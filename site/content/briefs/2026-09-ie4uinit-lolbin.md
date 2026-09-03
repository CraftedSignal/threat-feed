---
title: Abuse of ie4uinit.exe from Non-Standard Directories
slug: 2026-09-ie4uinit-lolbin
description: Adversaries may abuse the legitimate ie4uinit.exe binary by executing it from unauthorized locations to facilitate command execution via maliciously crafted .inf files.
date: "2026-09-03T13:46:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lolbin
  - defense-evasion
  - persistence
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The binary is abused as a LOLBin to proxy execution of arbitrary commands.
    confidence_band: high
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Ie4uinit/
  - https://bohops.com/2018/03/10/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence-part-2/
rules:
  - title: Detect Abuse of ie4uinit.exe from Non-Standard Directories
    description: Detects the execution of ie4uinit.exe from directories other than C:\Windows\System32 or C:\Windows\SysWOW64, which may indicate LotL abuse.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to hunt for historical abuse
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in brief
  mitigation_plan:
    - priority: medium_term
      action: Implement endpoint path restrictions or application control to block binary execution from user-writeable directories
      owner: IT Operations
      addresses: T1218
      evidence: Known technique documentation
---

The binary ie4uinit.exe (HTML Application Initializer) is a legitimate Windows system component often used for administrative tasks. Threat actors abuse this binary as a Living-off-the-Land (LotL) technique to proxy execution of arbitrary commands. By placing a specially prepared ie4uinit.inf file in a directory and triggering ie4uinit.exe from that same location, an attacker can coerce the binary into executing commands defined within the INF file. This technique is used for bypass, evasion, and persistence. Monitoring for instances where ie4uinit.exe is executed from paths other than the standard System32 or SysWOW64 directories allows defenders to identify potential abuse of this LOLBin.

## Attack Chain

1. Attacker identifies a writeable directory on the target system (e.g., C:\Users\Public\).
2. Attacker creates a malicious ie4uinit.inf file containing commands for execution within the target directory.
3. Attacker drops or moves a copy of ie4uinit.exe into the same directory as the malicious .inf file.
4. Attacker executes ie4uinit.exe from the non-standard path using a command-line interface.
5. The binary parses the local ie4uinit.inf file instead of the intended system configuration.
6. The binary executes the malicious commands defined in the .inf file with the privileges of the invoking user.
7. Persistence is established or secondary payloads are downloaded.

## Impact

Successful abuse of this technique allows an attacker to bypass security controls that restrict execution based on known binary paths, execute arbitrary commands under the user context, and establish persistence, potentially leading to full system compromise.

## Recommendation

Deploy the provided Sigma rule to monitor process creation events for ie4uinit.exe execution occurring outside of verified system directories. Investigate any instances triggered by this rule, specifically inspecting the current working directory and the existence of local .inf files.
