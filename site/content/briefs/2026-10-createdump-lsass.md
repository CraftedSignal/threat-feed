---
title: Credential Dumping via Createdump.exe
slug: 2026-10-createdump-lsass
description: Attackers are utilizing createdump.exe, a utility often bundled with third-party software like PowerShell 7, to dump LSASS memory for credential theft.
date: "2026-10-12T18:03:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows
  - lateral-movement
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: This activity is significant as it may indicate an attempt to dump LSASS memory, which can be used to extract credentials.
    confidence_band: high
rules:
  - title: Detect Createdump.exe LSASS Memory Dumping
    description: Detects the use of createdump.exe with command-line arguments indicative of process memory dumping, often used for LSASS credential theft.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to the SIEM and tune against established administrative baselines.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for createdump.exe detection.
  hunt_leads:
    - lead: Search for historical process creation events involving createdump.exe that deviate from known legitimate application paths.
      technique_id: T1003.001
      data_needed:
        - Process creation logs with command lines
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Documentation identifies createdump.exe as a non-native utility requiring specific baseline identification.
---

The utility createdump.exe, frequently included with non-native Windows applications such as .NET and PowerShell 7, is being leveraged by threat actors to perform process memory dumps. This utility is increasingly observed as a vehicle for dumping the Local Security Authority Subsystem Service (LSASS) process memory. Because createdump.exe is often present in standard enterprise environments, defenders must distinguish between legitimate diagnostic operations and malicious credential harvesting. Successful exploitation of this technique allows attackers to acquire cleartext passwords, NTLM hashes, or Kerberos tickets from memory, facilitating lateral movement and privilege escalation within the compromised network.

## Attack Chain

1. Attacker gains initial access to a Windows endpoint and establishes command execution capabilities.
2. Attacker identifies the presence of createdump.exe within third-party application directories (e.g., .NET runtime paths).
3. Attacker executes createdump.exe via command line, targeting the LSASS process ID or name.
4. The utility is invoked with specific arguments, typically '-u' (for user-mode) and '-f' (to specify a destination file path).
5. Createdump.exe reads the memory space of the LSASS process and writes the contents to a minidump file on disk.
6. Attacker exfiltrates the resulting dump file or processes it locally using tools like Mimikatz or Pypykatz.
7. Attacker parses the dumped memory to extract high-privilege credentials.
8. Attacker utilizes stolen credentials to move laterally or escalate privileges across the domain.

## Impact

The abuse of createdump.exe for credential dumping directly compromises the security of the Windows host. Successful extraction of LSASS memory often leads to domain-wide account takeovers, as attackers gain access to administrative credentials stored in memory. This technique is frequently associated with actors targeting high-value environments for exfiltration and long-term persistence.

## Recommendation

* Deploy the provided Sigma rule to monitor for suspicious command-line patterns involving createdump.exe.
* Review baseline fleet activity for createdump.exe to establish an allowlist of legitimate paths and parent processes.
* Enable Sysmon Event ID 1 (Process Creation) or Windows Event ID 4688 to capture full command-line arguments for createdump.exe.
* Restrict write access to directories where dump files are created to mitigate the impact of successful dumping.
