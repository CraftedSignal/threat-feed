---
title: Suspicious Execution from WebDAV Share
slug: 2024-01-webdav-execution
description: This rule detects attempts to execute content from remote WebDAV shares, where attackers may abuse WebDAV paths, public tunnels, or host@port UNC paths to execute tools or scripts, reducing local staging on the victim's file system.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - execution
  - webdav
  - windows
  - threat_detection
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Windows
  - Elastic Endgame
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Crowdstrike
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_scripting_remote_webdav.toml
rules:
  - title: WebDAV Share Execution via Suspicious Process
    description: Detects command-line execution from WebDAV shares using suspicious processes like cmd, powershell, and others.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
  - title: WebDAV Share Execution via Curl
    description: Detects command-line execution from WebDAV shares using curl.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies attempts to execute or invoke content directly from remote WebDAV shares on Windows systems. Attackers may abuse WebDAV paths, public tunnels (like trycloudflare.com), or host@port UNC paths to run tools or scripts while minimizing local staging on the victim file system. The detection focuses on specific command-line patterns indicative of WebDAV usage, such as paths containing "trycloudflare.com", "@SSL", "\\webdav\\", "\\DavWWWRoot\\", "*.*@8080", "*.*@80", "*.*@8443", or "*.*@443". The rule is designed to identify potentially malicious activity involving the execution of processes like cmd.exe, powershell.exe, conhost.exe, wscript.exe, mshta.exe, curl.exe, msiexec.exe, bitsadmin.exe, and net.exe from WebDAV shares. This technique can bypass traditional security measures that rely on detecting locally staged malware. The rule has been in production since 2025/08/19, and updated on 2026/05/03, demonstrating ongoing relevance.

## Attack Chain

1.  The attacker gains initial access to the target system (e.g., through phishing or exploiting a vulnerability).
2.  The attacker identifies a WebDAV share accessible from the target system, potentially hosted on a public tunnel like trycloudflare.com or using a non-standard port.
3.  The attacker crafts a malicious command that executes a script or binary directly from the remote WebDAV share using cmd.exe, powershell.exe, or similar tools.
4.  The command line includes a WebDAV path, such as `\\webdav\`, `\DavWWWRoot\`, or a UNC path with a port number like `\\host@8080\`.
5.  The target system attempts to retrieve and execute the specified file from the WebDAV share.
6.  The executed script or binary performs malicious actions, such as downloading additional payloads, establishing persistence, or exfiltrating data.
7.  The attacker may use tools like mshta.exe or bitsadmin.exe to bypass security restrictions and facilitate the execution of the malicious code.
8.  The attacker achieves their objective, which may include data theft, system compromise, or ransomware deployment.

## Impact

Successful exploitation allows attackers to execute arbitrary code on the target system without writing files to disk, making detection more difficult. Compromised systems can be used to steal sensitive data, establish a foothold for further attacks, or disrupt business operations. The absence of locally staged files hinders forensic analysis and incident response. Organizations are at risk of data breaches, financial losses, and reputational damage.

## Recommendation

*   Deploy the Sigma rule "WebDAV Share Execution via Suspicious Process" to detect command-line execution from WebDAV shares using specified processes and command-line patterns. Enable process creation logging with command line arguments on Windows systems (Sysmon Event ID 1 or Windows Security Event Logs) to ensure the rule functions correctly.
*   Deploy the Sigma rule "WebDAV Share Execution via Curl" to detect command-line execution from WebDAV shares specifically using curl. This rule complements the general WebDAV execution detection by focusing on a specific tool. Ensure network connection logging is enabled to capture curl's network activity.
*   Review and harden WebDAV and WebClient configurations to restrict unnecessary usage. Implement application control or attack surface reduction policies to limit direct execution from remote shares, as recommended in the "Post-incident hardening" section of the report.
*   Investigate any alerts generated by the rules, focusing on the launcher identity, parent lineage, child processes, and network connections, as outlined in the "Triage and analysis" section to determine if the activity is malicious or a legitimate use of WebDAV.
