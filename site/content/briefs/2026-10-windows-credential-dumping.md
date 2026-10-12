---
title: Detection of LSASS Credential Dumping via Suspicious Process Access
slug: 2026-10-windows-credential-dumping
description: This analytic identifies potential credential dumping by detecting unauthorized processes requesting suspicious access masks to the Local Security Authority Subsystem Service (LSASS).
date: "2026-10-12T18:17:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows
  - endpoint-detection
vendors:
  - Microsoft
products:
  - Local Security Authority Subsystem Service (LSASS)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The following analytic detects possible credential dumping by identifying suspicious process access to LSASS with credential-dumping-related call traces.
    confidence_band: high
rules:
  - title: Detect Potential LSASS Credential Dumping via Suspicious Access Mask
    description: Detects processes requesting PROCESS_QUERY_LIMITED_INFORMATION or PROCESS_DUP_HANDLE access to LSASS.exe, which is commonly associated with credential dumping tools.
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
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the LSASS access detection rule to the SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic provided by splunk-escu.
  hunt_leads:
    - lead: Search for instances of unauthorized processes attempting to open a handle to LSASS.exe.
      technique_id: T1003.001
      data_needed:
        - Sysmon Event ID 10
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Credential dumping is a high-priority post-exploitation activity.
  mitigation_plan:
    - priority: short_term
      action: Enable Credential Guard to protect LSASS memory.
      owner: IT Operations
      addresses: T1003.001
      evidence: Microsoft security best practices.
---

This detection analytic identifies potential credential dumping activities by monitoring for unauthorized processes attempting to interact with the Local Security Authority Subsystem Service (LSASS) process. Credential dumping is a common technique used by threat actors, including ransomware groups, to extract sensitive information such as plaintext credentials, hashes, or Kerberos tickets from memory. This alert leverages Sysmon Event ID 10 to identify processes that request specific, sensitive access masks - specifically PROCESS_QUERY_LIMITED_INFORMATION (0x1000) or PROCESS_DUP_HANDLE (0x40) - while utilizing common system-related call traces (e.g., dbghelp.dll or ntdll.dll). This behavior is frequently associated with the execution of tools like Mimikatz or Cobalt Strike beacons, which leverage these access levels to facilitate memory dumping. Defenders should monitor for these access attempts from processes other than authorized security services to identify and interrupt unauthorized memory access.

## Attack Chain

1. The adversary gains initial access to a Windows endpoint and establishes a foothold.
2. The adversary identifies a target process (LSASS.exe) for credential theft.
3. The adversary executes a tool, such as Mimikatz, to interact with the memory space of LSASS.
4. The tool makes a process access request to LSASS.exe using PROCESS_QUERY_LIMITED_INFORMATION or PROCESS_DUP_HANDLE.
5. The tool leverages Windows APIs such as MiniDumpWriteDump, often via calls to dbghelp.dll or ntdll.dll.
6. The adversary extracts credentials or secrets from the memory dump.
7. The extracted credentials are used to move laterally within the network or escalate privileges.

## Impact

Successful credential dumping often leads to the compromise of administrative credentials, enabling lateral movement, privilege escalation, and persistent access across the target environment. This technique is a precursor to widespread data exfiltration and ransomware deployment, significantly increasing the potential for enterprise-wide business disruption.

## Recommendation

* Enable Sysmon Event ID 10 across all Windows endpoints to monitor process access requests.
* Deploy the provided Sigma rule to your SIEM to identify suspicious access masks to LSASS.
* Establish a baseline of legitimate processes that require query access to LSASS to reduce false positives.
* Investigate any alerts originating from unexpected binaries, particularly those executing in user-space or from suspicious temporary directories.
