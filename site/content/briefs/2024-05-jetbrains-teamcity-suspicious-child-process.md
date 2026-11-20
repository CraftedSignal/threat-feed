---
brief_id: brief-2024-05-15-jetbrains-teamcity-suspicious-child-process
event_id: brief-2024-05-15-jetbrains-teamcity-suspicious-child-process
revision: 2
activity_at: "2026-11-20T01:37:27Z"
revision_history:
  - revision: 2
    at: "2026-11-20T01:37:27Z"
    checksum: sha256:195140e5574eeb1e64b3e716748b81f5557183534381e7ba080893f1cd3e566e
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
title: Suspicious Child Processes Spawned by JetBrains TeamCity
slug: 2024-05-jetbrains-teamcity-suspicious-child-process
description: Detection of suspicious processes spawned by JetBrains TeamCity indicates potential exploitation of remote code execution vulnerabilities, with attackers using command interpreters and system binaries for malicious purposes.
date: "2024-05-15T12:00:00Z"
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
  - teamcity
  - supply-chain
  - initial-access
vendors:
  - JetBrains
products:
  - TeamCity
affected_os:
  - Windows
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
rules:
  - title: Suspicious TeamCity Process Spawning Command Interpreter
    description: Detects suspicious command interpreters (cmd.exe, powershell.exe) spawned by the TeamCity Java process, indicating potential exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1059.003
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Suspicious TeamCity Process Spawning System Binary Proxy
    description: Detects suspicious system binary proxies (mshta.exe, regsvr32.exe) spawned by the TeamCity Java process.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - initial_access
    techniques:
      - T1190
      - T1218
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

JetBrains TeamCity is a continuous integration and deployment server, making it a high-value target for attackers. Exploitation of TeamCity vulnerabilities can lead to remote code execution, enabling adversaries to compromise the software development pipeline. This activity is detected by monitoring for suspicious child processes initiated by the TeamCity Java executable, focusing on executables like `cmd.exe`, `powershell.exe`, and `msiexec.exe`. The detection logic excludes legitimate operations to reduce false positives. This activity can lead to complete compromise of the build environment, allowing attackers to inject malicious code into software builds.

## Attack Chain

1. **Initial Access:** An attacker exploits a vulnerability (e.g., CVE-2023-42793) in the TeamCity server to gain initial access.
2. **Code Execution:** The attacker leverages the vulnerability to execute arbitrary code on the TeamCity server.
3. **Process Spawning:** The attacker spawns a command interpreter, such as `cmd.exe` or `powershell.exe`, from the TeamCity Java process (`java.exe`).
4. **Discovery:** The attacker uses discovery commands via the spawned shell to enumerate users, network configuration, and running processes using tools like `whoami.exe`, `ipconfig.exe`, and `tasklist.exe`.
5. **Defense Evasion:** The attacker leverages system binary proxy execution using tools like `mshta.exe` or `regsvr32.exe` to evade detection.
6. **Persistence:** While not explicitly mentioned, the attacker could establish persistence by creating scheduled tasks or modifying registry keys via spawned processes.
7. **Lateral Movement:** The attacker uses discovered credentials to move laterally to other systems within the network.
8. **Impact:** The attacker injects malicious code into software builds, compromises sensitive data, or deploys ransomware.

## Impact

Successful exploitation of JetBrains TeamCity can lead to a full compromise of the software development lifecycle, resulting in supply chain attacks. Attackers can inject malicious code into software builds, leading to widespread distribution of compromised software. While specific victim counts are unavailable, this type of attack has the potential to affect numerous organizations relying on the compromised software. The Trend Micro research indicates that TeamCity vulnerability exploits can lead to Jasmin ransomware deployment.

## Recommendation

*   Deploy the "Suspicious JetBrains TeamCity Child Process" rule to your SIEM to detect potential exploitation attempts.
*   Enable Sysmon process creation logging to capture process execution events, which are essential for triggering the detection rule.
*   Review and patch any known vulnerabilities in JetBrains TeamCity, focusing on remote code execution flaws as described in the referenced Trend Micro report.
*   Implement network segmentation to limit the impact of a compromised TeamCity server and prevent lateral movement.
*   Continuously monitor TeamCity server logs for any unusual activity or unauthorized access attempts.
*   Tune the "Suspicious JetBrains TeamCity Child Process" rule by creating exceptions for legitimate build scripts that invoke command-line utilities to reduce false positives, as mentioned in the rule's documentation.
