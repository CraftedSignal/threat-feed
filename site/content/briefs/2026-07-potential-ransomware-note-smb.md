---
title: Potential Ransomware Note File Dropped via SMB
slug: 2026-07-potential-ransomware-note-smb
description: Elastic has released a detection rule to identify the creation of ransomware note files by the Windows System process (PID 4) via the SMB protocol, indicating a remote ransomware attack often leveraging lateral movement to perform data encryption, destruction, or inhibit system recovery.
date: "2026-07-15T10:58:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ransomware
  - smb
  - windows
  - impact
  - lateral-movement
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Identifies the creation of a file with a name similar to ransomware note files by the Windows System process (PID 4). This may indicate a remote ransomware attack via the SMB protocol. This often accompanies remote rename, delete, or other drop activity.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: Identifies the creation of a file with a name similar to ransomware note files by the Windows System process (PID 4). This may indicate a remote ransomware attack via the SMB protocol.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: Identifies the creation of a file with a name similar to ransomware note files by the Windows System process (PID 4). Ransomware may place notes apart from encryption or recovery inhibition.
    confidence_band: med
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Identifies the creation of a file... by the Windows System process (PID 4). This may indicate a remote ransomware attack via the SMB protocol.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/impact_ransomware_note_file_over_smb.toml
rules:
  - title: Potential Ransomware Note File Dropped via SMB
    description: Detects the creation of files by the Windows System process (PID 4) with names and extensions commonly associated with ransomware notes, indicating a potential remote ransomware attack over SMB.
    platform: sigma
    severity: high
    tactics:
      - impact
      - lateral_movement
    techniques:
      - T1021
      - T1021.002
      - T1485
      - T1486
      - T1490
    data_sources:
      - file_event
      - windows
      - sysmon
rules_count: 1
---

Elastic has developed a high-severity detection rule aimed at identifying remote ransomware attacks leveraging the Server Message Block (SMB) protocol. This rule specifically targets the creation of files with names indicative of ransomware notes (e.g., containing "read me," "lock," "decrypt," "RECOVER") and common extensions (HTA, TXT, README, HTM/HTML) by the Windows System process (PID 4). The presence of such files, particularly in user profile paths or root directories, initiated by PID 4, strongly suggests an attacker has gained remote access and is performing lateral movement over SMB to drop these notes. This activity often precedes or accompanies data encryption, destruction, or actions designed to inhibit system recovery, posing a critical threat to data availability and integrity. Defenders should focus on investigating the context of these file creations, including the remote source IP and user identity, to differentiate malicious activity from legitimate system operations.

## Attack Chain

1. **Initial Access**: Threat actors gain unauthorized access to an internal network segment, typically through compromised credentials, exploited vulnerabilities, or social engineering.
2. **Lateral Movement**: Attackers utilize the compromised access to move within the network, identifying target systems and accessible shares.
3. **SMB Exploitation/Access**: The threat actor establishes an SMB connection to a target Windows host, leveraging either legitimate but compromised credentials or SMB vulnerabilities.
4. **Remote File Write via System Process**: Through the SMB connection, the attacker initiates file creation operations on the target system. These operations are executed by the Windows System process (PID 4) on behalf of the remote user.
5. **Ransomware Note Drop**: Multiple files identified as ransomware notes (e.g., "README.txt," "HOW_TO_DECRYPT.hta") are created in various user profile directories (`C:\Users\*`) or directly in root directories (`C:\`).
6. **Data Impact Preparation**: The dropped notes serve to communicate demands or instructions, often preceding or signaling the imminent encryption or destruction of data on the affected system.
7. **Data Encryption/Destruction**: (Potential) The attacker proceeds to encrypt, delete, or otherwise render critical data inaccessible on the compromised host and potentially other accessible shares.
8. **System Recovery Inhibition**: (Potential) Attackers may also take steps to disable backup mechanisms or delete shadow copies to hinder recovery efforts.

## Impact

Successful execution of this attack chain leads to severe consequences, primarily data loss, system unavailability, and significant operational disruption. Organizations could face substantial financial costs associated with recovery, potential ransom payments, reputational damage, and regulatory penalties. The targeted sectors are broad, as any organization with vulnerable Windows systems or weak SMB security controls is at risk. If the attack succeeds, critical business data may be permanently encrypted or destroyed, making recovery without backups challenging or impossible, and potentially leading to prolonged system downtime. The presence of ransomware notes confirms an active or imminent ransomware incident, demanding immediate and decisive incident response.

## Recommendation

* **Deploy the Sigma rule** "Potential Ransomware Note File Dropped via SMB" to your SIEM and tune for your environment to detect file creations by PID 4 matching ransomware note patterns.
* **Enable Sysmon Event ID 11 logging** for file creation events on Windows endpoints, particularly focusing on `process.pid`, `UserSid`, `TargetFilename`, and `Extension` fields, to ensure the rule's conditions are met.
* **Monitor network connection logs** for unusual SMB activity (destination port 445) to hosts, especially from unexpected `source.ip` addresses or user accounts, as suggested in the Elastic investigation guide.
* **Investigate file events** on affected hosts, focusing on `event.action`, `file.path`, `file.extension`, and `file.Ext.original.path` to identify broader destructive or staging behavior accompanying note drops.
* **Review related security alerts** on the host over 48 hours for other impact-related signals (e.g., shadow copy deletion, backup tampering) as outlined in the Elastic investigation guide's `investigate_2` section.
