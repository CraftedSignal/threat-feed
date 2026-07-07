---
title: Uncommon WMIC System Information Discovery by Aurora Stealer
slug: 2026-07-uncommon-wmic-system-info-discovery
description: Aurora Stealer has been observed using the Windows Management Instrumentation Command-line (WMIC) utility to perform extensive system reconnaissance, gathering details like OS version, CPU, GPU, disk drives, memory, and display resolution, indicating early-stage information gathering for subsequent data exfiltration or malware deployment.
date: "2026-07-03T14:52:52Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Aurora Stealer
tags:
  - windows
  - reconnaissance
  - discovery
  - infostealer
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: Detects the use of the WMI command-line (WMIC) utility to identify and display various system information, including OS, CPU, GPU, and disk drive names; memory capacity; display resolution; and baseboard, BIOS, and GPU driver products/versions. Some of these commands were used by Aurora Stealer in late 2022/early 2023.
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/a2ccd19c37d0278b4ffa8583add3cf52060a5418/atomics/T1082/T1082.md#atomic-test-25---system-information-discovery-with-wmic
  - https://nwgat.ninja/getting-system-information-with-wmic-on-windows/
  - https://blog.sekoia.io/aurora-a-rising-stealer-flying-under-the-radar
  - https://blog.cyble.com/2023/01/18/aurora-a-stealer-using-shapeshifting-tactics/
  - https://app.any.run/tasks/a6aa0057-82ec-451f-8f99-55650ca37da/
  - https://www.virustotal.com/gui/file/d6f6bc10ae0e634ed4301d584f61418cee18e5d58ad9af72f8aa552dc4aaeca3/behavior
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wmic_recon_system_info_uncommon.yml
rules:
  - title: Uncommon WMIC System Information Discovery
    description: Detects the use of WMIC.exe by attackers to gather specific system information like OS, logical disks, and hardware details, as observed in Aurora Stealer campaigns.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

In late 2022 and early 2023, the Aurora Stealer malware leveraged uncommon commands executed via the Windows Management Instrumentation Command-line (WMIC) utility for system reconnaissance. This infostealer, known for its shapeshifting tactics, utilized WMIC to enumerate detailed host characteristics including operating system caption, architecture, and version; logical disk names, sizes, and free space; as well as CPU, GPU, memory, display resolution, baseboard, and BIOS information. This activity represents a critical initial information gathering phase within an attacker's kill chain, enabling them to tailor subsequent attack stages, identify valuable data for exfiltration, or confirm suitability for further malware deployment. Defenders need to recognize these specific WMIC queries as indicators of malicious reconnaissance rather than benign system administration.

## Impact

While WMIC-based system information discovery is not directly destructive, its successful execution by threats like Aurora Stealer provides adversaries with a comprehensive understanding of the compromised environment. This reconnaissance enables attackers to identify high-value targets, plan lateral movement, and streamline data exfiltration efforts. For infostealers like Aurora, detailed system information can be crucial for tailoring further malware stages or selecting specific data types to steal, increasing the likelihood of successful data breach and financial or intellectual property loss. Organizations targeted may face significant reputational damage, regulatory fines, and costs associated with incident response and remediation.

## Recommendation

*   Deploy the provided Sigma rule "Uncommon WMIC System Information Discovery" to your SIEM solution and tune it for your environment to detect suspicious `wmic.exe` commands.
*   Ensure Sysmon or equivalent process creation logging is enabled on all Windows endpoints to capture command-line arguments for `wmic.exe`.
*   Regularly review `wmic.exe` process creation events for uncommon or unauthorized command-line parameters.
*   Educate users and administrators about the appropriate use of administrative tools like WMIC to help distinguish legitimate activity from malicious.
