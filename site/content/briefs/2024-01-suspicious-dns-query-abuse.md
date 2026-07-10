---
title: Suspicious Process DNS Queries to Known Abuse Web Services
slug: 2024-01-suspicious-dns-query-abuse
description: This analytic detects suspicious processes such as cmd.exe and powershell.exe making DNS queries to known, abused web services like Pastebin, Discord, and Telegram, potentially indicating malicious file downloads for initial access.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dns
  - malware
  - initial-access
vendors:
  - Microsoft
products:
  - Microsoft Office
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://urlhaus.abuse.ch/url/1798923/
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
iocs:
  - type: url
    value: https://urlhaus.abuse.ch/url/1798923/
ioc_counts:
  url: 1
rules:
  - title: Suspicious Process DNS Query Known Abuse Web Services
    description: Detects suspicious processes making DNS queries to known, abused text-paste web services, VoIP, instant messaging, and digital distribution platforms.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.005
    data_sources:
      - dns_query
      - windows
  - title: Suspicious Process Image DNS Query Known Abuse Web Services
    description: Detects suspicious processes with images from unusual locations making DNS queries to known, abused web services, VoIP, instant messaging, and digital distribution platforms.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1059.005
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

This detection identifies suspicious process behavior related to DNS queries targeting web services known for abuse. It specifically focuses on processes like `cmd.exe`, `powershell.exe`, and scripting hosts resolving domains associated with text-paste services (e.g., Pastebin), VoIP platforms (e.g., Discord), instant messaging (e.g., Telegram), and digital distribution platforms. The activity is flagged as suspicious due to the potential for malicious actors to leverage these services for command and control (C2) communication, hosting malicious payloads, or distributing malware downloaders. Successful exploitation can lead to unauthorized code execution, data exfiltration, and system compromise. This activity began being tracked in early 2022 with malware like WhisperGate using similar methods.

## Attack Chain

1.  A user inadvertently executes a malicious document or script delivered via phishing or other means.
2.  The malicious script (e.g., PowerShell) is launched, often from a compromised process like a macro-enabled Office document.
3.  The script initiates a DNS query to a Pastebin-like service to retrieve a malicious payload or further instructions using `QueryName IN ("*pastebin*", "*discord*", "*api.telegram*","*t.me*")`.
4.  The script downloads the payload from the web service using tools like `powershell.exe` or `cmd.exe`.
5.  The downloaded payload is executed, potentially leading to further exploitation.
6.  The payload establishes persistence through scheduled tasks or registry modifications.
7.  The compromised system communicates with a command and control (C2) server to receive further instructions.
8.  The attacker performs lateral movement and data exfiltration.

## Impact

Successful exploitation can lead to the execution of malicious code, data exfiltration, or ransomware deployment. Victims may experience data loss, system instability, and financial losses due to incident response and recovery efforts. This technique has been observed in various malware campaigns, including those distributing stealers, keyloggers, and ransomware, impacting organizations across multiple sectors. The WhisperGate malware, for example, used similar techniques to target Ukrainian organizations.

## Recommendation

*   Enable Sysmon Event ID 22 (DNS Query) logging on all endpoints to provide the data source for the provided Sigma rules.
*   Deploy the provided Sigma rule `Suspicious Process DNS Query Known Abuse Web Services` to your SIEM and tune the `process_name` and `Image` filters for your environment.
*   Investigate any alerts triggered by the provided Sigma rules, prioritizing those involving processes running from unusual locations like `\users\public\`, `\programdata\`, `\temp\`, `\Windows\Tasks\`, `\appdata\`, or `\perflogs\`.
*   Block access to the URL listed in the IOC table, `https://urlhaus.abuse.ch/url/1798923/`, at your network perimeter to prevent access to potentially malicious content.
