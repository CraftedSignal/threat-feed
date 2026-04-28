---
title: Lotus Data Wiper Targeting Venezuelan Energy and Utility Firms
slug: 2026-04-lotus-wiper
description: The Lotus wiper, a previously undocumented data-wiping malware, was deployed against Venezuelan energy and utilities organizations in 2025, overwriting physical drives, deleting files, and rendering systems unrecoverable.
date: "2026-04-22T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - data-wiper
  - lotus-wiper
  - venezuela
  - energy
  - utilities
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://www.bleepingcomputer.com/news/security/new-lotus-data-wiper-used-against-venezuelan-energy-utility-firms/
rules:
  - title: Detect UI0Detect Service Modification
    description: Detects changes to the UI0Detect service, potentially indicating preparation for Lotus wiper deployment.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Diskpart Clean All Execution
    description: Detects the execution of diskpart with the 'clean all' command, indicative of disk wiping activities.
    platform: sigma
    severity: critical
    tactics:
      - destruction
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
  - title: Detect suspicious Robocopy usage for data overwriting
    description: Detects Robocopy being used to overwrite directory contents, a technique used by the Lotus wiper.
    platform: sigma
    severity: high
    tactics:
      - destruction
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

In 2025, a new data wiper malware known as Lotus was used in targeted attacks against Venezuelan energy and utility companies. The malware, discovered by Kaspersky researchers after being uploaded to a public platform in mid-December 2025 from a Venezuelan machine, aims to completely destroy compromised systems. The attacks coincide with a period of geopolitical tension in the region. The malware not only overwrites data but also removes recovery mechanisms, overwrites the content of physical drives, and systematically deletes files across affected volumes, ultimately leaving the system in an unrecoverable state. The attackers used a series of batch scripts to prepare the environment before deploying the final Lotus wiper payload.

## Attack Chain

1. Initial execution of a batch script (`OhSyncNow.bat`) to disable the Windows `UI0Detect` service.
2. `OhSyncNow.bat` performs an XML file check for coordinated execution.
3. Execution of a second-stage batch script (`notesreg.bat`) when specific conditions are met.
4. `notesreg.bat` enumerates users, disables accounts by changing passwords, logs off active sessions, disables all network interfaces, and deactivates cached logins.
5. The malware enumerates drives and executes `diskpart clean all` to overwrite drives with zeros.
6. `robocopy` is used to overwrite directory contents.
7. The malware calculates free space and uses `fsutil` to create a file that fills the disk, hindering data recovery.
8. The batch script decrypts and executes the Lotus wiper, which overwrites physical sectors, clears USN journal entries, and wipes restore points. The final step updates disk properties using `IOCTL_DISK_UPDATE_PROPERTIES`.

## Impact

The Lotus wiper attacks against Venezuelan energy and utility firms in 2025 resulted in complete data loss and system unrecoverability. The attacks aimed to disrupt operations by destroying systems and eliminating any possibility of data recovery. While the exact number of affected organizations isn't specified, the impact of such attacks on critical infrastructure can be significant, potentially affecting energy distribution and essential services for the population. The attacks coincide with a period of geopolitical tension, suggesting a potential motive of sabotage or disruption.

## Recommendation

*   Monitor for changes to the NETLOGON share, as this is a potential indicator of compromise (see Overview).
*   Alert on modifications to the `UI0Detect` service state using a `registry_set` Sigma rule to identify potential initial stages of the attack (see Rules).
*   Implement detection rules to identify the execution of `diskpart`, `robocopy`, and `fsutil` with parameters related to data wiping activities using `process_creation` Sigma rules (see Rules).
*   Monitor for mass account changes and disabling of network interfaces, as these are precursor activities (see Overview).
*   Maintain regular offline backups and validate their restorability frequently to mitigate the impact of data wipers (see Overview).
