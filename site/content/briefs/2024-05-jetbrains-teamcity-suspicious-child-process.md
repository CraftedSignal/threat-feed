---
title: Suspicious Child Processes Spawned by JetBrains TeamCity
slug: 2024-05-jetbrains-teamcity-suspicious-child-process
description: Detection of suspicious processes spawned by JetBrains TeamCity indicates potential exploitation of remote code execution vulnerabilities, with attackers using command interpreters and system binaries for malicious purposes.
date: "2024-05-15T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
    epss: 0.92913
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
---

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
