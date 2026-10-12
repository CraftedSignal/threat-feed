---
title: Detection of LSASS Memory Dumping via Sysmon
slug: 2026-10-lsass-dump-detection
description: This brief details the detection of credential dumping attempts targeting the LSASS process memory, often observed in campaigns by actors such as Scattered Lapsus$ or during ransomware deployment.
date: "2026-10-12T17:35:50Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Microsoft
products:
  - lsass.exe
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The following analytic detects attempts to dump the LSASS process memory, a common technique in credential dumping attacks.
    confidence_band: high
rules:
  - title: Detect Access to LSASS Memory for Dump Creation
    description: Detects processes attempting to dump LSASS memory by checking for call traces to dbgcore.dll or dbghelp.dll in Sysmon Event ID 10 events.
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
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 24h
      evidence: Source provides specific logic for detecting T1003.001 via Sysmon Event 10
  hunt_leads:
    - lead: Search for historical Sysmon Event 10 activity targeting lsass.exe
      technique_id: T1003.001
      data_needed:
        - Sysmon Event ID 10
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source indicates this technique is frequently used by ransomware actors
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict Credential Guard policies on Windows endpoints
      owner: IT Operations
      addresses: T1003.001
      evidence: LSASS credential dumping is mitigated by virtualization-based security
---

Adversaries frequently target the Local Security Authority Subsystem Service (LSASS) process on Windows systems to extract sensitive credentials, including plaintext passwords, NTLM hashes, and Kerberos tickets. By dumping the process memory of lsass.exe, attackers can facilitate privilege escalation, lateral movement, and persistence. This activity is a hallmark of sophisticated post-exploitation toolkits and is commonly associated with ransomware operations (e.g., Cactus Ransomware) and information stealers (e.g., Lokibot). Defenders should monitor for unauthorized processes attempting to obtain handle access to lsass.exe using specific system debugging libraries. The detection focuses on Sysmon Event ID 10 logs identifying calls to dbgcore.dll or dbghelp.dll, which are standard components used by dumping utilities.

## Attack Chain

1. The attacker gains initial access to a Windows host.
2. The attacker elevates privileges to Administrator or SYSTEM level.
3. The attacker deploys a memory-dumping tool or executes native Windows commands (e.g., ProcDump, comsvcs.dll via rundll32.exe).
4. The dumping tool initiates a process handle request to lsass.exe with specific access rights (e.g., PROCESS_QUERY_LIMITED_INFORMATION or PROCESS_VM_READ).
5. The dumping tool utilizes the Windows APIs dbghelp.dll or dbgcore.dll to facilitate the memory read operation.
6. The memory dump file (e.g., lsass.dmp) is written to the local disk.
7. The attacker exfiltrates the dump file or processes it locally using tools like Mimikatz to extract credentials.

## Impact

Successful LSASS memory dumping grants an adversary access to cleartext credentials and authentication material for all users logged into the system. This level of access typically leads to full domain compromise, as attackers can leverage stolen administrative credentials to move laterally, access critical servers, and deploy ransomware or exfiltrate sensitive data.

## Recommendation

1. Enable Windows Sysmon and configure Event ID 10 (ProcessAccess) logging to track handles requested against lsass.exe.
2. Deploy the provided Sigma rule to identify suspicious library imports associated with memory dumping.
3. Audit environments for the presence of known credential dumping tools like Mimikatz, ProcDump, or Cobalt Strike beacons.
4. Restrict administrative privileges to limit the ability of non-privileged users to request handles on sensitive system processes.
