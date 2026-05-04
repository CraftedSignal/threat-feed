---
title: Unusual System Utilities Initiating Network Connections
slug: 2024-01-unusual-process-network
description: Adversaries may leverage unusual system utilities such as Microsoft.Workflow.Compiler.exe, bginfo.exe, cdb.exe, cmstp.exe, csi.exe, dnx.exe, fsi.exe, ieexec.exe, iexpress.exe, odbcconf.exe, rcsi.exe and xwizard.exe to execute code and evade detection, as identified by network connections originating from these processes.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - proxy-execution
  - windows
vendors:
  - Elastic
  - SentinelOne
products:
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_unusual_process_network_connection.toml
  - https://attack.mitre.org/techniques/T1127/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/003/
  - https://attack.mitre.org/techniques/T1218/008/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Unusual Process Network Connection - CMSTP
    description: Detects network connections initiated by cmstp.exe, which may indicate Living-off-the-Land attacks.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.003
    data_sources:
      - network_connection
      - windows
  - title: Unusual Process Network Connection - Ieexec
    description: Detects network connections initiated by ieexec.exe, which may indicate Living-off-the-Land attacks.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Attackers frequently exploit built-in system utilities to bypass security measures and execute malicious code. This technique, known as "Living off the Land," allows them to blend in with legitimate system activity, making detection more challenging. This threat brief focuses on identifying unusual network connections originating from Windows system utilities that are not typically associated with network communication. This behavior is often indicative of an attacker leveraging these tools for purposes such as downloading payloads, establishing command and control, or exfiltrating data. The utilities of concern include: Microsoft.Workflow.Compiler.exe, bginfo.exe, cdb.exe, cmstp.exe, csi.exe, dnx.exe, fsi.exe, ieexec.exe, iexpress.exe, odbcconf.exe, rcsi.exe and xwizard.exe. Defenders should monitor for network activity from these processes to identify potential malicious activity.

## Attack Chain

1.  An attacker gains initial access to a Windows system through methods such as phishing or exploiting a vulnerability.
2.  The attacker leverages a system utility such as `cmstp.exe` to execute malicious code.
3.  `cmstp.exe` is invoked with a malicious INF file, leading to the execution of arbitrary commands.
4.  The executed code initiates a network connection to an external server.
5.  The connection is used to download a secondary payload, such as a reverse shell or malware.
6.  The attacker uses the downloaded payload to establish a persistent presence on the system.
7.  The attacker performs lateral movement to other systems on the network.
8.  The attacker exfiltrates sensitive data from compromised systems to a remote server.

## Impact

A successful attack can lead to a compromised system with unauthorized code execution, data exfiltration, and potential lateral movement within the network. Due to the low severity and the high probability of false positives, this rule should be tuned for specific environments and paired with other detection mechanisms. This may lead to data breaches, financial loss, or reputational damage.

## Recommendation

*   Implement the Sigma rules provided in this brief to detect unusual network connections from system utilities within your environment.
*   Monitor process execution events for the utilities listed in the rule query to identify potential abuse of these tools.
*   Enable Sysmon Event ID 1 (Process Creation) and Event ID 3 (Network Connection) logging for enhanced visibility into process execution and network activity.
*   Correlate detections from this rule with other security alerts and logs to gain a more complete understanding of the attack.
