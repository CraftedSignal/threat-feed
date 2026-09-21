---
title: Credential Theft via LSASS Memory Dumping using Task Manager
slug: 2026-09-lsass-dump-taskmgr
description: Adversaries may use the legitimate Windows Task Manager utility to create a memory dump of the Local Security Authority Subsystem Service (LSASS) process to harvest sensitive credentials.
date: "2026-09-21T19:11:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-dumping
  - windows
  - endpoint-security
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
    evidence: The following analytic detects the creation of an lsass.exe process dump using Windows Task Manager.
    confidence_band: high
rules:
  - title: Detect LSASS Memory Dump via Task Manager
    description: Detects the creation of an lsass.dmp file originating from taskmgr.exe, a common technique for credential harvesting.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule provided for Sysmon Event ID 11.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search historical file creation logs for any instances of lsass*.dmp files.
      technique_id: T1003.001
      data_needed:
        - Sysmon Event ID 11
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Creation of lsass dump file is a high-fidelity indicator of credential theft.
---

Adversaries often target the Local Security Authority Subsystem Service (LSASS) process, as it resides in memory and contains critical authentication material, including NTLM hashes and Kerberos tickets. A documented method for achieving this is using the built-in Windows Task Manager (taskmgr.exe) to initiate a dump of the process memory. By right-clicking the lsass.exe process in Task Manager and selecting "Create dump file," an attacker generates a full memory image of the process. This activity is a significant indicator of credential dumping attempts, which are typically precursors to lateral movement or further privilege escalation within a compromised Windows environment. Defenders must monitor for the resulting dump files, which are saved by default to the user's temporary folder, as this behavior is rarely required for routine system administration.

## Impact

Successful dumping of LSASS memory allows attackers to gain unauthorized access to plaintext passwords, NTLM hashes, and Kerberos tickets. With these credentials, an attacker can impersonate users, move laterally through a network, and achieve persistent access, ultimately leading to full domain compromise or the deployment of ransomware.

## Recommendation

Prioritize monitoring for unauthorized file creation events involving LSASS memory dumps and restrict administrative privileges to prevent interactive use of Task Manager on sensitive systems.
* Enable Sysmon Event ID 11 to track file creation activity on all endpoints.
* Deploy the detection rule provided in this brief to identify the creation of lsass.dmp via Task Manager.
* Audit and restrict the use of administrative tools like Task Manager on domain-joined workstations and servers.
* Investigate any findings triggered by this rule, as LSASS dumps are rarely performed by legitimate administrative processes.
