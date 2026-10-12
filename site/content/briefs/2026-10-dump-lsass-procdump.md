---
title: Credential Dumping via Sysinternals Procdump
slug: 2026-10-dump-lsass-procdump
description: Adversaries utilize the legitimate Sysinternals utility procdump.exe to extract sensitive credentials from the LSASS process memory to facilitate lateral movement and privilege escalation.
date: "2026-10-12T17:43:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - windows
  - credential-dumping
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
    evidence: The following analytic detects the use of procdump.exe to dump the LSASS process.
    confidence_band: high
rules:
  - title: Detect LSASS Memory Dumping via Procdump
    description: Detects the use of procdump.exe or its renamed variants with command-line arguments (-ma, -mm, -mp) targeting the LSASS process.
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
    - action: Deploy Sigma rule to monitor for procdump execution targeting LSASS.
      owner: Detection Engineering
      due: 24h
      evidence: Analytics description
  hunt_leads:
    - lead: Search for historical process creation logs for procdump or renamed variations.
      technique_id: T1003.001
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of adversary behavior
---

The abuse of the Sysinternals utility procdump.exe is a common technique employed by threat actors to perform credential dumping by accessing the memory space of the Local Security Authority Subsystem Service (LSASS). This activity involves spawning the procdump process with specific flags, such as -ma (full dump) or -mm (mini dump), aimed at a target process like lsass.exe. By extracting these memory dumps, attackers can recover cleartext passwords, NTLM hashes, and Kerberos tickets, effectively compromising the security of the Windows host. This technique is frequently observed in post-exploitation scenarios, including those associated with groups such as HAFNIUM and activities documented in CISA AA22-257A. Defenders should prioritize visibility into process-level telemetry to identify the invocation of these binaries with suspicious command-line parameters.

## Attack Chain

1. Attacker establishes initial access or gains sufficient privileges on a Windows host.
2. Attacker stages the legitimate Sysinternals utility procdump.exe on the target file system.
3. Attacker identifies the process ID (PID) of the lsass.exe service.
4. Attacker executes procdump.exe with command-line arguments (e.g., -ma, -mm) targeting the lsass process.
5. The Windows OS grants the process access to the LSASS memory space if the attacker has sufficient privileges.
6. Procdump creates a memory dump file containing sensitive authentication material.
7. Attacker exfiltrates or parses the dump file offline using tools like Mimikatz or Pypykatz to obtain credentials.
8. Attacker uses extracted credentials to move laterally within the network or escalate privileges.

## Impact

Successful execution of this attack allows unauthorized actors to harvest domain credentials and sensitive authentication tokens. This exposure often leads to complete environment compromise, enabling persistent lateral movement, unauthorized access to sensitive data, and further privilege escalation across the domain.

## Recommendation

* Deploy the provided Sigma rule to detect process-creation events where procdump is invoked with suspicious flags targeting lsass.
* Implement endpoint monitoring for process creation events (Sysmon Event ID 1) and map these to the CIM 'Processes' node.
* Restrict access to and monitor the usage of administrative utilities like Sysinternals tools in standard user environments.
* Audit and remediate unauthorized administrative accounts that can be used to facilitate LSASS memory dumping.
