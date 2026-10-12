---
title: Detection of Credential Access via Registry Hive Export
slug: 2026-10-windows-registry-hive-dump
description: Attackers leverage legitimate Windows binaries like reg.exe and regedit.exe to export sensitive SAM, SECURITY, and SYSTEM hives for offline credential theft and lateral movement.
date: "2026-10-12T18:21:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - windows
  - registry-abuse
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
    evidence: This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving save or export actions targeting the sam, system, or security hives.
    confidence_band: high
rules:
  - title: Detect Sensitive Windows Registry Hive Export
    description: Detects the use of reg.exe or regedit.exe to export sensitive SAM, SECURITY, or SYSTEM registry hives, a common credential dumping technique.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.002
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
    - action: Deploy the Sigma rule to monitor for registry hive export commands.
      owner: Detection Engineering
      due: 24h
  hunt_leads:
    - lead: Search historical logs for reg.exe or regedit.exe command line patterns involving SAM, SECURITY, or SYSTEM keywords.
      technique_id: T1003.002
      data_needed:
        - Process creation logs (Event ID 1)
      priority: medium
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: medium
      action: Review administrative access permissions to critical registry hives.
      owner: IT Operations
---

Adversaries frequently target the Windows Registry to extract sensitive credential material, a technique categorized as credential dumping. By utilizing built-in system utilities such as `reg.exe` or `regedit.exe`, attackers can export the SAM (Security Accounts Manager), SECURITY, and SYSTEM hives. Once these hives are exported as files, they can be exfiltrated or processed offline to recover password hashes. This activity is a classic example of "living off the land," where standard administrative tools are repurposed for malicious gain. Monitoring for these specific command-line execution patterns is critical for identifying potential unauthorized access to the local security database, which often precedes broader lateral movement and privilege escalation within an enterprise environment. This technique has been observed in various campaigns, including ransomware operations and activity attributed to state-sponsored actors.

## Attack Chain

1. Initial access is established on a target Windows host via phishing, exploitation, or credential reuse.
2. The attacker gains execution privileges on the endpoint, typically at the standard user or administrator level.
3. The attacker identifies the necessity of obtaining local credentials to facilitate lateral movement or domain dominance.
4. The attacker invokes `reg.exe` or `regedit.exe` to target the `HKLM\SAM`, `HKLM\SECURITY`, or `HKLM\SYSTEM` registry hives.
5. The attacker executes export or save commands (e.g., `reg save HKLM\SAM c:\temp\sam.save`) to dump the hives into flat files.
6. The resulting hive files are moved to a staging directory to prepare for exfiltration or offline parsing.
7. The attacker uses tools like Mimikatz or Impacket to parse the dumped hives for password hashes.
8. The final objective is the acquisition of cleartext passwords or NTLM hashes to move laterally to other systems or domain controllers.

## Impact

Successful execution of this technique provides attackers with the raw material to crack passwords or pass-the-hash. This directly leads to unauthorized access to other network resources, privilege escalation, and significant data exfiltration risk. Numerous high-profile intrusions and ransomware groups have utilized this method to compromise target environments, potentially affecting every machine where the attacker attains administrative execution.

## Recommendation

- Deploy the provided Sigma rules to detect unauthorized use of `reg.exe` or `regedit.exe` targeting sensitive registry hives.
- Implement monitoring for process execution of `reg.exe` where the parent process is an unusual user-mode application or script (e.g., PowerShell, WMI, or unknown binaries).
- Enable Sysmon or Windows Security Event ID 4688 to capture comprehensive command-line arguments to improve visibility into administrative tool abuse.
- Establish a baseline for administrative actions and alert on deviations originating from non-IT-managed accounts or processes.
