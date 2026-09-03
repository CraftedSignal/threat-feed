---
title: Detection of LSASS Memory Dumping via Command Line Keywords
slug: 2026-09-lsass-dump-cli-keywords
description: Detection of credential access attempts targeting the Local Security Authority Subsystem Service (LSASS) process via command-line arguments indicative of memory dump creation.
date: "2026-09-03T12:45:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - windows
  - security-monitoring
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Detects the presence of the keywords 'lsass' and '.dmp' in the commandline, which could indicate a potential attempt to dump or create a dump of the lsass process.
    confidence_band: high
rules:
  - title: Detect LSASS Memory Dump via Command Line Keywords
    description: Detects the presence of the keywords 'lsass' and '.dmp' in the command line, indicating potential attempts to dump the lsass process memory.
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
    - action: Deploy the LSASS dump keyword detection rule to the SIEM environment
      owner: Detection Engineering
      due: 48h
      evidence: Rule documentation for proc_creation_win_susp_lsass_dmp_cli_keywords
  hunt_leads:
    - lead: Search historical logs for processes accessing lsass.exe or creating .dmp files
      technique_id: T1003.001
      data_needed:
        - Process command line logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of common LSASS dump filenames and patterns
---

This brief addresses the detection of unauthorized attempts to dump the memory contents of the Local Security Authority Subsystem Service (LSASS) process. Attackers frequently target LSASS to extract sensitive credentials, such as cleartext passwords, NTLM hashes, and Kerberos tickets, which can then be used for lateral movement and privilege escalation. Common techniques for dumping LSASS memory include the use of legitimate system tools like procdump, specialized post-exploitation frameworks like nanodump or MirrorDump, and various custom scripts. These methods often involve creating output files containing the process memory. Monitoring process creation logs for specific command-line indicators - such as filenames containing 'lsass' or extension markers like '.dmp' - allows security teams to identify and respond to credential access attempts in real-time. This detection logic is critical for identifying post-exploitation activity where attackers attempt to bypass traditional credential dumping tools that might otherwise be blocked by security software.

## Impact

Successful dumping of LSASS memory provides attackers with the necessary credentials to escalate privileges to Domain Admin or perform lateral movement across the network. Compromised credentials can lead to full domain compromise, data exfiltration, and long-term persistence within an organization's environment. Because LSASS dumping is a precursor to further malicious actions, identifying this behavior early in the attack lifecycle is essential for limiting the blast radius of an intrusion.

## Recommendation

- Deploy the provided Sigma rule to monitor for command-line arguments involving LSASS memory dump operations.
- Enable Sysmon or Windows Event Log (Event ID 4688) with full command-line logging to ensure visibility into process execution.
- Investigate any triggered alerts immediately to distinguish between malicious activity and authorized administrative or diagnostic tasks.
- Supplement process-based detection with memory access monitoring (e.g., using EDR telemetry) to detect direct calls to the LSASS process, as some advanced tools may avoid standard command-line indicators.
