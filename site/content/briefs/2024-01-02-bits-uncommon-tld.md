---
title: BITS Transfer Job With Uncommon or Suspicious Remote TLD
slug: 2024-01-02-bits-uncommon-tld
description: Adversaries abuse Background Intelligent Transfer Service (BITS) to download malicious payloads from unusual top-level domains, bypassing traditional security measures and establishing persistence on compromised systems.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.defense-evasion
  - attack.persistence
  - attack.t1197
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1197
    technique_name: BITS Jobs
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1197
    technique_name: BITS Jobs
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1197/T1197.md
  - https://twitter.com/malmoeb/status/1535142803075960832
rules:
  - title: BITS Transfer Job to Non-Standard TLD
    description: Detects BITS transfer jobs downloading files from domains with uncommon TLDs.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - persistence
    techniques:
      - T1197
    data_sources:
      - bits-client
      - windows
  - title: BITS Transfer Job to Suspicious Subdomain
    description: Detects BITS transfer jobs downloading files from suspicious subdomains.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - persistence
    techniques:
      - T1197
    data_sources:
      - bits-client
      - windows
rules_count: 2
---

The Background Intelligent Transfer Service (BITS) is a Windows service that transfers files in the background. Attackers abuse BITS to download malware, exfiltrate data, or maintain persistence. This rule focuses on detecting BITS activity involving unusual or suspicious top-level domains (TLDs) or subdomains. Legitimate uses of BITS often involve well-known Microsoft domains or content delivery networks. Attackers may use less common TLDs or subdomains to evade detection. By monitoring BITS transfers to uncommon domains, analysts can identify potentially malicious activity that bypasses standard web filtering and intrusion detection systems. This activity started being tracked in June 2022 and continues to be relevant due to its built-in functionality within Windows.

## Attack Chain

1.  The attacker gains initial access to the system through an exploit or social engineering.
2.  The attacker uses PowerShell or cmd.exe to create a new BITS transfer job.
3.  The BITS job is configured to download a malicious payload from a remote server with an uncommon TLD.
4.  The BITS service initiates the download in the background.
5.  The malicious payload is saved to disk, often in a hidden or temporary directory.
6.  The attacker executes the downloaded payload using PowerShell, cmd.exe, or another scripting engine.
7.  The payload establishes persistence through registry keys or scheduled tasks.
8.  The attacker achieves their objective, such as data exfiltration, lateral movement, or ransomware deployment.

## Impact

Successful exploitation via BITS can lead to a range of adverse outcomes, including malware infection, data theft, and system compromise. Since BITS operates in the background, users may not be aware of the malicious activity, allowing attackers to maintain persistence and control over the compromised system undetected. The lack of user interaction makes it difficult to attribute the attack to user error, complicating incident response efforts. While the exact number of victims is unknown, this technique is prevalent across various sectors due to BITS's widespread availability on Windows systems.

## Recommendation

*   Deploy the Sigma rule "BITS Transfer Job With Uncommon or Suspicious Remote TLD" to your SIEM and tune for your environment to detect potentially malicious BITS activity.
*   Monitor the BITS-Client service logs on Windows endpoints for EventID 16403 to identify new transfer jobs.
*   Investigate any BITS transfer jobs that involve remote names outside of the filter\_main\_generic list.
*   Implement stricter egress filtering to block connections to uncommon or suspicious TLDs.
*   Consider enabling Sysmon process creation logging to correlate BITS activity with subsequent process executions.
