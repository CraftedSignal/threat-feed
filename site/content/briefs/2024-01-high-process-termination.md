---
title: High Number of Process and/or Service Terminations Detected
slug: 2024-01-high-process-termination
description: A high number of process terminations (stop, delete, or suspend) from the same Windows host within a short time period may indicate malicious activity such as an attacker attempting to disable security measures or prepare for ransomware deployment.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - impact
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.elastic.co/security-labs/luna-ransomware-attack-pattern
  - https://attack.mitre.org/techniques/T1489/
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/001/
  - https://attack.mitre.org/tactics/TA0040/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: High Number of Process Terminations via Taskkill
    description: Detects a high number of process terminations using taskkill.exe within a short period, indicative of potential malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1489
      - T1562
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: High Number of Service Terminations via SC
    description: Detects a high number of service terminations using sc.exe within a short period, which is a sign of an attacker trying to disable services.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1489
      - T1562
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies a suspicious pattern of rapid process and service terminations on a Windows host. Attackers commonly stop services and kill processes to disable security tools, release file locks for encryption, or disrupt normal system operations. The rule specifically looks for multiple instances of termination-related commands executed via `net.exe`, `sc.exe`, or `taskkill.exe` within a short timeframe. This activity can be indicative of an attacker preparing a system for ransomware deployment or attempting to evade defenses. The detection focuses on Windows systems, leveraging process monitoring logs. This behavior aligns with tactics used to impair defenses and achieve significant impact on compromised systems.

## Attack Chain

1.  The attacker gains initial access to the Windows host (e.g., through phishing or exploitation).
2.  The attacker escalates privileges to obtain necessary permissions to terminate processes and services.
3.  The attacker uses `net.exe` to stop specific services, such as backup solutions or security software.
4.  The attacker employs `sc.exe` to delete services, preventing them from restarting automatically.
5.  The attacker utilizes `taskkill.exe` with flags like `/F`, `/IM`, or `/PID` to forcefully terminate processes.
6.  The attacker repeats these steps, rapidly terminating multiple processes and services.
7.  The attacker prepares the system for ransomware deployment by disabling security measures.
8.  The attacker deploys ransomware, encrypting data and demanding a ransom for its recovery.

## Impact

Successful exploitation leads to disruption of critical services, disabling of security controls, and potential data loss. If an attacker successfully terminates security solutions, they can significantly increase the likelihood of successful ransomware deployment or data exfiltration. The impact can range from temporary service outages to complete system compromise and data encryption, resulting in financial losses, reputational damage, and operational disruption.

## Recommendation

*   Deploy the `High Number of Process Terminations via Taskkill` and `High Number of Service Terminations via SC` Sigma rules to your SIEM and tune for your environment.
*   Investigate any alerts triggered by the rules, focusing on the processes terminated and the user accounts involved.
*   Enable process creation logging with command-line arguments to ensure the rules have sufficient data to function effectively.
*   Review the references provided to understand attacker techniques and improve detection strategies.
*   Implement network segmentation to limit the lateral movement of attackers.
*   Regularly review and update security policies to prevent unauthorized process termination.
