---
title: Credential Dumping via rundll32 and comsvcs.dll
slug: 2026-10-dump-lsass-comsvcs
description: Adversaries leverage the legitimate comsvcs.dll library to dump the LSASS process memory via rundll32.exe, enabling unauthorized credential extraction from Windows systems.
date: "2026-10-12T17:43:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*
tags:
  - credential-access
  - windows
  - living-off-the-land
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The following analytic detects the behavior of dumping credentials from memory by exploiting the Local Security Authority Subsystem Service (LSASS) using the comsvcs.dll.
    confidence_band: high
references:
  - https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
  - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
rules:
  - title: Detect LSASS Memory Dumping via comsvcs.dll
    description: Detects the use of rundll32.exe to execute the MiniDump function within comsvcs.dll for the purpose of dumping LSASS memory.
    platform: sigma
    severity: high
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM.
      owner: Detection Engineering
      due: 24h
      evidence: High signal for credential dumping.
  hunt_leads:
    - lead: Search for rundll32.exe processes with command lines referencing comsvcs.dll and memory dump files.
      technique_id: T1003.001
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Standard LotL TTP.
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict Least Privilege model.
      owner: IT Operations
      addresses: Credential dumping vectors.
      evidence: Reduces impact of unauthorized LSASS access.
---

Adversaries exploit the native Windows comsvcs.dll library to perform memory dumping of the Local Security Authority Subsystem Service (LSASS) process. This technique, commonly executed via rundll32.exe, bypasses traditional file-based detection by using a trusted system binary to interact with the MiniDump API. This activity is frequently observed in post-exploitation scenarios, allowing attackers to harvest plaintext credentials, NTLM hashes, and Kerberos tickets stored in memory. Successfully dumping LSASS memory provides adversaries with the necessary material for lateral movement, privilege escalation, and persistence across a target environment. This technique has been documented in association with various threat actors, including Volt Typhoon, as a core component of living-off-the-land (LotL) strategies. Defenders must focus on identifying the specific command-line arguments and process behaviors associated with the MiniDump export function to mitigate credential theft.

## Attack Chain

1. Attacker achieves initial execution on a Windows endpoint using a persistent mechanism or payload.
2. Attacker enumerates active processes to identify the Process ID (PID) of the lsass.exe service.
3. Attacker identifies a requirement to escalate privileges or move laterally, necessitating local credential access.
4. Attacker invokes the native rundll32.exe binary to execute functions within the comsvcs.dll dynamic link library.
5. The command line includes the MiniDump argument and the PID of lsass.exe to generate a memory dump file.
6. Rundll32.exe performs the memory dump operation, writing the contents of LSASS memory to a file on disk (e.g., C:\Windows\Temp\lsass.dmp).
7. Attacker exfiltrates the resulting dump file to an external command-and-control server or secondary internal host.
8. Attacker uses credential-cracking tools (e.g., Mimikatz, Pypykatz) on the dump file to extract plaintext passwords and hashes.

## Impact

Successful credential dumping leads to a complete compromise of the affected host's identity secrets. Attackers use these harvested credentials to impersonate users, access domain-joined resources, and perform unauthorized lateral movement. In large environments, this often results in domain-wide privilege escalation and the subsequent deployment of ransomware or long-term data exfiltration.

## Recommendation

1. Deploy the Sigma rules below to detect rundll32.exe invocations targeting lsass.exe via comsvcs.dll.
2. Implement endpoint detection and response (EDR) logging for process creation, ensuring capture of the full command line, parent process, and process GUID.
3. Restrict administrative permissions on endpoints to prevent unauthorized users from interacting with high-integrity processes like LSASS.
4. Monitor for the creation of files with the .dmp extension in system directories, which may indicate the successful conclusion of an LSASS dump operation.
