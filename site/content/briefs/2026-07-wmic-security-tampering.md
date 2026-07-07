---
title: Potential Tampering With Security Products Via WMIC
slug: 2026-07-wmic-security-tampering
description: Threat actors, including those behind IcedID, LockBit, and Vice Society, actively utilize the Windows Management Instrumentation Command-line (WMIC) utility to uninstall or terminate security products, aiming to impair host defenses and facilitate ransomware deployment or data exfiltration.
date: "2026-07-03T15:00:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-impairment
  - tampering
  - wmic
  - windows
  - lolbin
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects uninstallation or termination of security products using the WMIC utility
    confidence_band: high
references:
  - https://twitter.com/cglyer/status/1355171195654709249
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
  - https://www.mandiant.com/resources/unc2165-shifts-to-evade-sanctions
  - https://research.nccgroup.com/2022/08/19/back-in-black-unlocking-a-lockbit-3-0-ransomware-attack/
  - https://www.trendmicro.com/en_us/research/23/a/vice-society-ransomware-group-targets-manufacturing-companies.html
rules:
  - title: Potential Tampering With Security Products Via WMIC
    description: Detects uninstallation or termination of security products using the WMIC utility, often employed by ransomware groups and other threat actors to impair host defenses.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Since at least 2021, various sophisticated threat actors and ransomware groups, such as IcedID, LockBit 3.0, Vice Society, and UNC2165, have incorporated the Windows Management Instrumentation Command-line (WMIC) utility into their attack chains to disable or uninstall endpoint security products. This technique, highlighted by a SigmaHQ rule updated in 2025, leverages legitimate system administration tools to achieve defense impairment by targeting common antivirus (AV), endpoint detection and response (EDR), and data loss prevention (DLP) solutions. By executing commands like `wmic product call uninstall` or `wmic process call delete` against security product processes, attackers aim to reduce detection capabilities, bypass preventative controls, and clear the path for subsequent malicious activities such as ransomware encryption, data exfiltration, or destructive attacks. This method is effective because WMIC is a living-off-the-land binary (LOLBIN) that is typically present on Windows systems, allowing attackers to blend in with legitimate system activity and complicate detection efforts.

## Attack Chain

1.  **Initial Access**: Threat actors gain an initial foothold, often through methods like phishing campaigns with malicious attachments or exploiting vulnerable internet-facing applications.
2.  **Execution & Foothold**: Malware payloads are delivered and executed, establishing persistence and potentially escalating privileges to administrative levels necessary for system modifications.
3.  **Internal Reconnaissance**: Attackers perform discovery actions to identify installed security products, their process names, and service configurations, often using tools like `tasklist` or WMIC itself.
4.  **Defense Impairment**: Using WMIC, attackers execute commands to uninstall security products (e.g., `wmic product where name="Sophos Anti-Virus" call uninstall /nointeractive`) or terminate their processes (e.g., `wmic process where "name like '%carbon%'" call delete`).
5.  **Credential Access & Lateral Movement**: With endpoint defenses weakened or removed, attackers move laterally across the network, escalating privileges and harvesting credentials.
6.  **Impact**: The final objective is achieved, which typically involves deploying ransomware for encryption, exfiltrating sensitive data, or performing other destructive actions without hindrance from security software.

## Impact

The successful tampering with or uninstallation of security products through WMIC directly leads to a significant degradation of an organization's defensive posture, leaving endpoints vulnerable to subsequent attacks. Victims may experience undetected ransomware deployment, leading to widespread data encryption and business disruption, as seen in campaigns involving LockBit 3.0 and Vice Society. Furthermore, the lack of active endpoint protection facilitates data exfiltration, intellectual property theft, and long-term network compromise by sophisticated actors like UNC2165. The cost of recovery can be substantial, encompassing system restoration, data recovery, incident response, and reputational damage.

## Recommendation

*   Deploy the provided Sigma rule "Potential Tampering With Security Products Via WMIC" to your SIEM/EDR platform to detect suspicious WMIC activity targeting security products.
*   Ensure Sysmon process-creation logging is enabled to provide the necessary telemetry for the detection rule.
*   Implement strong tamper protection features provided by your endpoint security solutions to prevent unauthorized uninstallation or service termination.
*   Review and baseline legitimate WMIC usage in your environment to reduce false positives for the detection rule, focusing on expected administrative scripts.
*   Conduct regular security awareness training, emphasizing the risks of phishing and social engineering, as these are common initial access vectors that precede defense impairment.
