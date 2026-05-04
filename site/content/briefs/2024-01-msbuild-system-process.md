---
title: MSBuild Started by System Process for Defense Evasion and Execution
slug: 2024-01-msbuild-system-process
description: Adversaries are leveraging MSBuild, a Microsoft Build Engine, to execute malicious code by initiating it from system processes such as Explorer or WMI to evade defenses and execute unauthorized actions.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - msbuild
  - proxy-execution
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - CrowdStrike
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_execution_msbuild_started_by_system_process.toml
  - https://attack.mitre.org/techniques/T1127/
  - https://attack.mitre.org/techniques/T1127/001/
  - https://attack.mitre.org/techniques/T1047/
rules:
  - title: Microsoft Build Engine Started by a System Process
    description: Detects instances of MSBuild.exe being started by explorer.exe or wmiprvse.exe, which is indicative of potential malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1047
      - T1127.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious MSBuild Project File Execution
    description: Detects MSBuild.exe executing project files from unusual locations, which could indicate malicious activity.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1127.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Microsoft Build Engine (MSBuild) is a legitimate tool used by developers to build applications. However, adversaries are known to abuse MSBuild to execute malicious code, leveraging its trusted status to bypass security measures. This technique allows attackers to perform various actions on compromised systems while blending in with legitimate system activity. The observed behavior involves MSBuild being started by system processes like Explorer (explorer.exe) or Windows Management Instrumentation (WMI, wmiprvse.exe). Defenders should be aware of this unusual activity as it signifies a potential defense evasion tactic and unauthorized code execution within the targeted environment. This activity has been observed across environments leveraging Elastic Defend, Microsoft Defender XDR, SentinelOne Cloud Funnel, CrowdStrike, and standard Windows event logging.

## Attack Chain

1. An attacker gains initial access to the system through various means (e.g., phishing, exploitation of vulnerabilities).
2. The attacker leverages a script or payload that invokes MSBuild.exe.
3. The script or payload is executed by a system process like explorer.exe or wmiprvse.exe, which is highly unusual for typical MSBuild usage.
4. MSBuild.exe starts with specific command-line arguments that dictate the build process, often involving malicious code.
5. The malicious code is embedded within an MSBuild project file (.csproj or similar).
6. MSBuild.exe executes the malicious code as part of the build process.
7. The executed code performs actions such as downloading additional payloads, modifying system configurations, or establishing persistence.
8. The attacker achieves their objective, such as gaining remote access, exfiltrating data, or deploying ransomware.

## Impact

Successful exploitation can lead to a variety of negative outcomes, including unauthorized code execution, system compromise, data theft, and potentially complete system takeover. The use of MSBuild as a proxy execution method allows attackers to evade traditional security controls and blend in with legitimate system activities. This can result in delayed detection and increased dwell time, amplifying the potential damage. Since MSBuild is a trusted Microsoft utility, its abuse can make malicious activity harder to identify and respond to.

## Recommendation

*   Deploy the Sigma rule "Microsoft Build Engine Started by a System Process" to your SIEM to detect instances of MSBuild.exe being launched by explorer.exe or wmiprvse.exe (see rules section).
*   Enable process creation logging with command line arguments to capture the full context of MSBuild.exe executions (reference setup instructions in the source URL).
*   Investigate any instances of MSBuild.exe started by explorer.exe or wmiprvse.exe to determine if they are legitimate or malicious.
*   Implement enhanced monitoring and logging for MSBuild.exe and related processes to detect similar activities in the future, ensuring alerts are configured for rapid response.
*   Review and whitelist any legitimate scripts or administrative tools that leverage MSBuild for authorized tasks to reduce false positives.
