---
brief_id: brief-2024-05-08-teamcity-child-process
event_id: brief-2024-05-08-teamcity-child-process
revision: 2
activity_at: "2026-11-20T01:37:27Z"
revision_history:
  - revision: 2
    at: "2026-11-20T01:37:27Z"
    checksum: sha256:2cb0a1d67074ce68dff7322ff32a7f7524afaecc4657fad7be521e37de4416ff
    summary: exploited:true; KEV CVE-2023-42793
    changed_fields:
      - cves
      - exploitation_evidence
      - lastmod
      - priority_score
      - priority_signals
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Suspicious JetBrains TeamCity Child Process Activity
slug: 2024-05-teamcity-child-process
description: Detection of suspicious processes spawned by JetBrains TeamCity indicates potential exploitation of remote code execution vulnerabilities.
date: "2024-05-08T14:30:00Z"
lastmod: "2026-11-20T01:36:50Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2023-10-04T00:00:00Z"
  confidence: high
tags:
  - jetbrains
  - teamcity
  - rce
  - supply-chain
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.001
    subtechnique_name: PowerShell
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    subtechnique_id: T1218.003
    subtechnique_name: CMSTP
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    subtechnique_id: T1218.004
    subtechnique_name: InstallUtil
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    subtechnique_id: T1218.005
    subtechnique_name: Mshta
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    subtechnique_id: T1218.007
    subtechnique_name: Msiexec
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    subtechnique_id: T1218.008
    subtechnique_name: Odbcconf
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    subtechnique_id: T1218.010
    subtechnique_name: Regsvr32
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    subtechnique_id: T1218.011
    subtechnique_name: Rundll32
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
    epss: 0.92913
    kev: true
    kev_status: "true"
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
updates:
  - at: "2026-11-20T01:36:50Z"
    level: L3
    summary: exploited:true; KEV CVE-2023-42793
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

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
