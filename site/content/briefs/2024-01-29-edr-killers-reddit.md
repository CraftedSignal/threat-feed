---
title: Discussion of EDR Killers on Reddit
slug: 2024-01-29-edr-killers-reddit
description: A Reddit post on r/blueteamsec references an ESET WeLiveSecurity article discussing EDR killer techniques that extend beyond driver manipulation.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - edr-evasion
  - defense-evasion
  - red-team
products:
  - Endpoint Detection and Response (EDR) solutions
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://www.reddit.com/r/blueteamsec/comments/1ry9din/edr_killers_explained_beyond_the_drivers/
  - https://www.welivesecurity.com/en/eset-research/edr-killers-explained-beyond-the-drivers/
rules:
  - title: Detect EDR Process Termination via Taskkill
    description: Detects the use of taskkill.exe to terminate processes potentially associated with EDR solutions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect EDR Service Disabling via Registry Modification
    description: Detects modifications to the start type of services that may be associated with EDR solutions.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1543.003
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This threat brief summarizes a discussion on the r/blueteamsec subreddit regarding "EDR killers." The post, submitted by user /u/rkhunter_, links to an article on WeLiveSecurity (ESET's blog) that explores techniques used by attackers to disable or bypass Endpoint Detection and Response (EDR) solutions. This discussion highlights the evolving tactics employed by threat actors to evade detection and maintain persistence within compromised environments. While the specifics of these "beyond the drivers" techniques aren't detailed in the Reddit post itself, the reference to ESET's research indicates a focus on advanced methods that go beyond simply unloading kernel drivers associated with EDR products. Defenders need to be aware of the broader spectrum of EDR evasion tactics to effectively protect their systems.

## Attack Chain

1.  **Initial Compromise:** Attacker gains initial access to the system through methods not specified in this brief.
2.  **Privilege Escalation:** The attacker escalates privileges to gain administrative or system-level access, a necessary step for many EDR killer techniques.
3.  **Discovery:** The attacker performs reconnaissance to identify the presence and configuration of EDR solutions installed on the system. This can involve querying system processes, registry keys, or file system locations.
4.  **EDR Service Enumeration:** Attacker enumerates the services associated with the EDR solution to identify potential targets for disabling or manipulation.
5.  **Process Termination:** The attacker attempts to terminate EDR-related processes using tools like `taskkill.exe` or by directly manipulating process handles.
6.  **Service Disabling:** The attacker attempts to disable EDR services by modifying their startup configuration in the registry or using tools like `sc.exe`.
7.  **Registry Modification:** The attacker modifies registry keys associated with the EDR to disable features, tamper with configurations, or prevent the EDR from starting.
8.  **Persistence:** The attacker establishes persistence using various methods to maintain access even if the EDR is re-enabled or the system is restarted.

## Impact

Successful execution of EDR killer techniques can severely impair an organization's ability to detect and respond to security incidents. With the EDR effectively disabled, attackers can operate with impunity, deploying malware, exfiltrating sensitive data, or launching ransomware attacks without immediate detection. The number of victims and sectors targeted depend on the attacker's objectives. The potential consequences include data breaches, financial losses, and reputational damage.

## Recommendation

*   Monitor for suspicious process terminations, particularly those targeting processes commonly associated with EDR solutions (Attack Chain, step 5). Deploy a Sigma rule to detect the use of `taskkill.exe` or similar tools to terminate EDR processes.
*   Implement monitoring for changes to service configurations, specifically focusing on services associated with EDR products (Attack Chain, step 6). Deploy a Sigma rule to detect modifications to the startup type of EDR services in the registry.
*   Enable Sysmon process creation and registry modification logging to provide the necessary data for the Sigma rules mentioned above.
*   Regularly review and update EDR configurations and signatures to address emerging evasion techniques.
