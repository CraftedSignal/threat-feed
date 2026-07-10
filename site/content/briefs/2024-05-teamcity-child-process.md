---
title: Suspicious JetBrains TeamCity Child Process Activity
slug: 2024-05-teamcity-child-process
description: Detection of suspicious processes spawned by JetBrains TeamCity indicates potential exploitation of remote code execution vulnerabilities.
date: "2024-05-08T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - jetbrains
  - teamcity
  - rce
  - supply-chain
vendors:
  - JetBrains
products:
  - TeamCity
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Connections Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1057
    technique_name: Process Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1482
    technique_name: Domain Trust Discovery
cves:
  - id: CVE-2023-42793
    cvss: 9.8
    epss: 0.99979
references:
  - https://www.trendmicro.com/en_us/research/24/c/teamcity-vulnerability-exploits-lead-to-jasmin-ransomware.html
  - https://attack.mitre.org/techniques/T1190/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1016/
  - https://attack.mitre.org/techniques/T1033/
  - https://attack.mitre.org/techniques/T1049/
  - https://attack.mitre.org/techniques/T1057/
  - https://attack.mitre.org/techniques/T1082/
  - https://attack.mitre.org/techniques/T1087/
  - https://attack.mitre.org/techniques/T1482/
rules:
  - title: Suspicious JetBrains TeamCity Child Process
    description: Detects suspicious processes spawned by the JetBrains TeamCity process, indicating potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - discovery
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1059.003
      - T1082
      - T1190
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: TeamCity Java Process Spawning Certutil
    description: Detects certutil being spawned by TeamCity Java process
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the potential exploitation of JetBrains TeamCity servers through the spawning of suspicious child processes. TeamCity, a continuous integration and deployment server, is a valuable target for attackers seeking to gain unauthorized access to software development pipelines. The observed behavior involves the execution of unusual processes by the TeamCity Java executable (java.exe). The exploitation of TeamCity vulnerabilities allows attackers to execute arbitrary code on the server, potentially leading to data breaches, supply chain compromise, or ransomware deployment. The activity has been observed starting in late March 2024, with ongoing campaigns leveraging various tools and techniques. Defenders should be vigilant for unexpected child processes initiated by TeamCity's Java process, especially those involving command-line interpreters or system administration tools.

## Attack Chain

1.  **Initial Access:** Attackers exploit a vulnerability in the TeamCity server software (e.g., CVE-2023-42793) to gain initial access.
2.  **Code Execution:** The exploitation allows attackers to execute arbitrary code within the context of the TeamCity server.
3.  **Process Spawning:** The attacker leverages the compromised TeamCity server to spawn a command shell (cmd.exe) or PowerShell process (powershell.exe).
4.  **Discovery:** The attacker uses the spawned shell to perform system discovery, gathering information about the environment using tools like `whoami.exe`, `hostname.exe`, `net.exe`, `nltest.exe`, `tasklist.exe`, `arp.exe`, `nbtstat.exe`, `netstat.exe`, `reg.exe`, and `systeminfo.exe`.
5.  **Lateral Movement:** Based on the discovered information, the attacker attempts to move laterally within the network, potentially using credentials or other access obtained from the TeamCity server.
6.  **Persistence:** The attacker establishes persistence on the compromised system, potentially through scheduled tasks or registry modifications.
7.  **Privilege Escalation:** The attacker attempts to escalate privileges on the compromised system.
8.  **Objective Completion:** The attacker achieves their final objective, which could include data exfiltration, deployment of ransomware, or disruption of software development processes.

## Impact

Successful exploitation of JetBrains TeamCity can lead to significant damage, including supply chain compromise, data breaches, and disruption of software development pipelines. Victims could experience financial losses, reputational damage, and legal liabilities. Given TeamCity's central role in software development, a successful attack can have cascading effects on downstream customers and partners.

## Recommendation

*   Deploy the Sigma rule "Suspicious JetBrains TeamCity Child Process" to your SIEM and tune it for your environment to detect suspicious child processes spawned by the TeamCity Java executable.
*   Review and patch any known vulnerabilities in JetBrains TeamCity, focusing on CVE-2023-42793, using the vendor's official guidance.
*   Monitor process creation events on TeamCity servers, specifically looking for the execution of command-line interpreters (cmd.exe, powershell.exe) and system administration tools by the TeamCity Java process, leveraging Windows Security Event Logs or Sysmon logs.
*   Implement network segmentation to limit the potential impact of a successful TeamCity compromise, referencing technique T1021.001 for lateral movement.
