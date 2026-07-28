---
title: Detection of Common Ransomware File Extension Modifications
slug: 2026-07-common-ransomware-extensions
description: This analytic identifies ransomware activity by detecting file creation or modification events on endpoint filesystems where the resulting file extensions match known ransomware patterns, potentially leading to significant data loss and operational disruption.
date: "2026-07-28T18:59:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ransomware
  - endpoint-detection
  - file-modification
  - impact
  - Rhysida Ransomware
  - Prestige Ransomware
  - LockBit Ransomware
  - Medusa Ransomware
  - SamSam Ransomware
  - Clop Ransomware
  - Ryuk Ransomware
  - Black Basta Ransomware
  - Termite Ransomware
  - Interlock Ransomware
  - NailaoLocker Ransomware
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: this activity could result in the encryption of critical data, rendering it inaccessible and causing significant damage to the organization's data integrity and availability.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/common_ransomware_extensions.yml
rules:
  - title: Detect Common Ransomware File Extension Renames (Sysmon Event 23)
    description: Detects file rename operations (Sysmon Event ID 23) where the destination filename matches extensions commonly associated with ransomware. This indicates potential data encryption by ransomware.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - file_event
      - windows
rules_count: 1
---

This brief describes an analytic designed to detect ransomware activity by monitoring for specific file extension changes on endpoint filesystems. The detection focuses on `created` or `modified` file actions where the new file extension corresponds to patterns frequently used by various ransomware families. While ransomware attacks commonly involve initial access, execution, and privilege escalation, this analytic specifically targets the impact stage where encryption occurs. The presence of files with these extensions, especially in large volumes, indicates that an attacker is actively encrypting or altering critical data, rendering it inaccessible. This activity, first created in October 2019 and updated in July 2026, leverages Endpoint.Filesystem data models, notably from Sysmon EventID 11 (FileCreate) and EventID 23 (FileRename), and highlights the immediate and severe risk of data loss and operational disruption for organizations.

## Attack Chain

1. **Initial Access**: Adversary gains unauthorized entry into the victim's network, often through phishing, exploiting vulnerable public-facing applications, or abusing valid accounts.
2. **Execution**: Malicious ransomware payloads are delivered and executed on compromised systems, sometimes via remote services, user-driven execution, or scheduled tasks.
3. **Persistence**: Ransomware establishes persistence mechanisms (e.g., modifying registry run keys, creating scheduled tasks) to maintain access and re-execute after system reboots.
4. **Discovery**: The ransomware binary enumerates local files, attached storage, and accessible network shares to identify valuable data for encryption.
5. **Defense Evasion**: The ransomware may attempt to disable security software, delete shadow copies, or clear event logs to hinder detection and recovery efforts.
6. **Encryption**: The ransomware encrypts target files on local drives and accessible network shares, often employing strong cryptographic algorithms.
7. **File Renaming**: Encrypted files are renamed with distinct, proprietary extensions (e.g., `.locked`, `.encrypt`, `.rnsm`) to signify their encrypted status. This specific action is a key indicator for the detection rule.
8. **Ransom Note Deployment**: Ransom notes containing demands, payment instructions, and threats of data publication are dropped in affected directories or displayed to the user.

## Impact

Successful ransomware attacks lead to the encryption of critical data, making it inaccessible to the victim organization. This can result in severe operational disruption, including system downtime, loss of business continuity, and potential financial costs associated with recovery efforts, ransom payments, and regulatory fines. Victims often face significant data recovery challenges and may lose unrecoverable data. While the number of victims and specific sectors are not detailed in this analytic, ransomware broadly targets organizations across all industries, aiming for maximum financial extortion.

## Recommendation

* Ensure ingestion of filesystem activity logs, specifically Sysmon EventID 11 (FileCreate) and EventID 23 (FileRename), to populate the Endpoint.Filesystem data model node for comprehensive endpoint visibility.
* Deploy the provided Sigma rule to detect file rename operations targeting common ransomware extensions.
* Review and implement correlation rules in your SIEM for Sysmon EventID 23 to identify a high volume of file renames occurring within a short timeframe, indicating bulk encryption activity by ransomware.
* Regularly back up critical data offline and test recovery procedures to minimize the impact of successful encryption.
