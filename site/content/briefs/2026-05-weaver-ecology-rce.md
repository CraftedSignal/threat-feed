---
title: Weaver E-cology Unauthenticated RCE Exploitation
slug: 2026-05-weaver-ecology-rce
description: A critical unauthenticated remote code execution vulnerability (CVE-2026-22679) in Weaver E-cology office automation software is being actively exploited to execute system commands and reconnaissance activities on affected servers.
date: "2026-05-05T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - rce
  - weaver-ecology
  - cve-2026-22679
  - exploitation
vendors:
  - Weaver
  - Microsoft
products:
  - E-cology 10.0
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
cves:
  - id: CVE-2026-22679
    cvss: 9.8
    epss: 0.00181
references:
  - https://www.bleepingcomputer.com/news/security/weaver-e-cology-critical-bug-exploited-in-attacks-since-march/
rules:
  - title: Detect Weaver E-cology RCE via Java Process
    description: Detects potential exploitation of Weaver E-cology RCE vulnerability by monitoring process creation events where java.exe is the parent process and the child process executes system commands.
    platform: sigma
    severity: critical
    tactics:
      - discovery
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Reconnaissance Activity After Weaver E-cology RCE
    description: Detects reconnaissance commands executed after a process spawned by java.exe, potentially indicating exploitation of Weaver E-cology vulnerability.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A critical unauthenticated remote code execution vulnerability, tracked as CVE-2026-22679, has been actively exploited in Weaver E-cology office automation software since mid-March 2026. The vulnerability impacts E-cology 10.0 builds prior to March 12, 2026, allowing attackers to execute arbitrary system commands without authentication. Threat actors were observed attempting to download and execute PowerShell-based payloads, as well as performing reconnaissance activities to gather information about the compromised systems. Weaver E-cology is primarily used by Chinese organizations. Defenders should prioritize patching vulnerable systems to prevent potential compromise and data exfiltration.

## Attack Chain

1.  The attacker exploits CVE-2026-22679, an unauthenticated RCE vulnerability in Weaver E-cology 10.0.
2.  The attacker sends a crafted HTTP request to an exposed debug API endpoint.
3.  The crafted request bypasses authentication and input validation, allowing the attacker to inject commands.
4.  The injected commands are executed as system commands within the context of the Java process (java.exe) hosting Weaver's Tomcat server.
5.  The attacker attempts to download and execute a target-aware MSI installer (fanwei0324.msi).
6.  The attacker uses obfuscated and fileless PowerShell to repeatedly fetch remote scripts after initial attempts are blocked by endpoint defenses.
7.  The attacker executes reconnaissance commands, such as `whoami`, `ipconfig`, and `tasklist`, to gather information about the compromised system.
8.  The attacker aims to establish a persistent session on the targeted host but, according to the report, has not been successful.

## Impact

Successful exploitation of CVE-2026-22679 allows attackers to execute arbitrary system commands on vulnerable Weaver E-cology servers, potentially leading to complete system compromise. The attackers can perform reconnaissance, install malware, exfiltrate sensitive data, or disrupt business operations. Given the software's use in workflows, document management, HR, and internal business processes, a successful attack could have significant consequences.

## Recommendation

*   Apply the security updates provided by Weaver to address CVE-2026-22679 on all E-cology 10.0 installations prior to build 20260312.
*   Monitor process creation events where the parent process is `java.exe` (Weaver's Tomcat-bundled Java Virtual Machine) for suspicious command-line arguments using the "Detect Weaver E-cology RCE via Java Process" Sigma rule.
*   Monitor for the creation of processes executing reconnaissance commands (`whoami`, `ipconfig`, `tasklist`) after java.exe, using the "Detect Reconnaissance Activity After Weaver E-cology RCE" Sigma rule.
*   Inspect network connections initiated by the `java.exe` process, filtering for connections to uncommon or suspicious destinations.
