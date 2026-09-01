---
title: Abuse of print.exe for Unauthorized File Transfer
slug: 2026-09-print-exe-abuse
description: Attackers can leverage the legitimate Windows print.exe utility to perform unauthorized remote file copying, facilitating data staging and exfiltration.
date: "2026-09-01T12:23:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - LOLBAS
  - file-transfer
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Attackers can use print.exe for remote file copy
    confidence_band: high
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Print/
  - https://twitter.com/Oddvarmoe/status/985518877076541440
rules:
  - title: Detect Abuse of print.exe for Remote File Copy
    description: Detects the use of print.exe to perform unauthorized remote file operations by monitoring for command lines that include the /D flag and an executable file reference.
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
  immediate_actions:
    - action: Deploy Sigma rule bafac3d6-7de9-4dd9-8874-4a1194b493ed to SIEM
      owner: Detection Engineering
      due: 72h
      evidence: Source provides concrete detection logic for LotL behavior.
  hunt_leads:
    - lead: Search for print.exe executions containing network shares or .exe extensions in the CommandLine
      technique_id: T1218
      data_needed:
        - Sysmon Event ID 1
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source identifies this command-line signature as suspicious.
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict application execution policies if print.exe is not required for daily business operations
      owner: IT Operations
      addresses: T1218
      evidence: Reducing surface area by disabling unnecessary binaries is standard hardening.
---

The Windows native utility print.exe has been identified as a Living off the Land (LotL) binary that can be abused to perform unauthorized file copies. By utilizing specific command-line arguments, an attacker can coerce the print service into interacting with remote files, effectively bypassing traditional file-copy detection mechanisms that monitor standard tools like robocopy.exe or powershell.exe. This technique allows for the stealthy movement of executables or sensitive data from remote locations to a local system. Defenders should monitor for command-line patterns involving the print.exe utility that indicate remote connectivity rather than standard local printing operations, as this behavior is rarely observed in typical office environments.

## Attack Chain

1. Attacker establishes initial access or presence on a target host.
2. Attacker stages a malicious executable on a remote network share or web server.
3. Attacker identifies print.exe as a permitted, signed binary on the target system.
4. Attacker executes print.exe via the command line, supplying the remote file path as an argument.
5. The utility triggers a request to the remote resource to pull the target file.
6. The remote file is copied to the local host filesystem.
7. Attacker executes the transferred file to achieve secondary payload delivery or data exfiltration.

## Impact

Successful abuse of print.exe enables adversaries to download malicious payloads or stage data for exfiltration while evading simple endpoint security controls. While specific incident counts are not provided, the technique is widely recognized within the LOLBAS (Living Off the Land Binaries and Scripts) framework, which serves as a repository for binaries commonly exploited by threat actors across various sectors to maintain persistence and bypass security software.

## Recommendation

- Deploy the provided Sigma rule to monitor for suspicious command-line invocations of print.exe.
- Enable Sysmon process-creation logging (Event ID 1) to capture the necessary Image and CommandLine fields.
- Review and baseline normal printing behavior in the environment to differentiate legitimate network printer interactions from malicious file transfers.
- Alert on or investigate any execution of print.exe that includes both the /D flag and references to non-printer related file extensions or remote paths.
