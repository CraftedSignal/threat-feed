---
title: Uncommon Process Loading RstrtMgr.DLL for Malicious Purposes
slug: 2026-07-uncommon-rstrtmgr-dll-load
description: Attackers, including ransomware families like Conti and Cactus, and wipers such as BiBi, abuse the legitimate Windows `RstrtMgr.dll` (Restart Manager) by loading it into uncommon processes to terminate applications, including security software and those holding locks on files, facilitating data encryption or destruction.
date: "2026-07-28T08:24:29Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - impact
  - ransomware
  - wiper
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: This library has been used during ransomware campaigns to kill processes that would prevent file encryption by locking them (e.g. Conti ransomware, Cactus ransomware).
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: This library has been used during ransomware campaigns to kill processes that would prevent file encryption by locking them (e.g. Conti ransomware, Cactus ransomware).
    confidence_band: high
references:
  - https://www.crowdstrike.com/blog/windows-restart-manager-part-1/
  - https://www.crowdstrike.com/blog/windows-restart-manager-part-2/
  - https://web.archive.org/web/20231221193106/https://www.swascan.com/cactus-ransomware-malware-analysis/
  - https://taiwan.postsen.com/business/88601/Hamas-hackers-use-data-destruction-software-BiBi-which-consumes-a-lot-of-processor-resources-to-wipe-Windows-computer-data--iThome.html
rules:
  - title: Load Of RstrtMgr.DLL By An Uncommon Process
    description: Detects the loading of RstrtMgr.dll by processes outside of common legitimate Windows system paths or software installation contexts, indicating potential malicious activity by ransomware or wiper malware.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1486
    data_sources:
      - image_load
      - windows
rules_count: 1
---

The `RstrtMgr.dll` (Restart Manager library) is a legitimate Windows component designed to facilitate the shutdown and restart of applications and services, particularly during software installations or updates. However, threat actors, notably ransomware groups like Conti and Cactus, and wiper malware such as BiBi, have co-opted this functionality for malicious purposes. By loading `RstrtMgr.dll` into an unexpected or malicious process, attackers can force the termination of critical applications, including antivirus software, endpoint detection and response (EDR) solutions, databases, and office applications. This technique is primarily used in the impact phase of an attack to clear obstacles for data encryption, data destruction, or to hinder analysis. The abnormal loading of this DLL by processes outside of typical Windows system or installer contexts is a strong indicator of compromise, suggesting an attacker is attempting to impair defenses or ensure the success of their destructive payload.

## Attack Chain

1. **Initial Compromise and Execution**: Attackers gain initial access to a system, often through phishing, exploitation of a public-facing application, or compromised credentials, and subsequently execute their malicious payload (e.g., ransomware or wiper).
2. **Privilege Escalation**: The malicious payload attempts to elevate its privileges to ensure it can perform system-level actions, including terminating processes belonging to other users or system accounts.
3. **Discovery**: The malware identifies target files, folders, and processes that might interfere with its primary objective of data encryption or destruction, such as database servers, email clients, and security software.
4. **Defense Evasion - Process Termination**: The malicious process loads the `RstrtMgr.dll` (Restart Manager library) to leverage its legitimate functionality. This allows the attacker to gracefully terminate applications that are holding locks on target files, hindering encryption/wiping, or to shut down security services that could detect or prevent the attack.
5. **Data Encrypted/Destroyed**: With critical processes terminated, the ransomware proceeds to encrypt files, or the wiper destroys data across the compromised system and accessible network shares, achieving the attacker's impact objective.
6. **Persistence/Cleanup (Optional)**: Depending on the specific malware, it may establish persistence mechanisms for future access or attempt to remove forensic artifacts to hinder incident response and analysis.

## Impact

The successful exploitation of `RstrtMgr.dll` by malicious actors leads to severe consequences. For ransomware campaigns, it ensures maximum damage by guaranteeing that files are not locked during encryption, resulting in complete data unavailability for the victim. In the case of wiper attacks, it facilitates the irreversible destruction of data, often rendering systems unrecoverable. This technique also aids in defense impairment by shutting down security solutions, allowing the attack to proceed unimpeded. Organizations across all sectors are vulnerable, as the technique targets a core Windows component. Victims face significant operational disruption, data loss, and potential financial losses due to recovery efforts or ransom payments.

## Recommendation

* Enable `ImageLoad` logging in your endpoint detection and response (EDR) or Sysmon configuration to activate the provided Sigma rule.
* Deploy the Sigma rule "Load Of RstrtMgr.DLL By An Uncommon Process" to your SIEM and tune for your environment to detect suspicious `RstrtMgr.dll` loads.
* Investigate all `low` level alerts generated by the "Load Of RstrtMgr.DLL By An Uncommon Process" rule, particularly if originating from non-standard executable paths or processes.
* Review the process hierarchy and command-line arguments for any process identified loading `RstrtMgr.dll` outside of expected system or installer contexts.
