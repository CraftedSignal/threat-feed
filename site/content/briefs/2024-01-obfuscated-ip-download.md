---
title: Detection of Obfuscated IP Address Usage in Download Commands
slug: 2024-01-obfuscated-ip-download
description: This brief details the use of obfuscated IP addresses within download commands, often employed to evade detection by hiding the true destination of malicious downloads.
date: "2024-01-27T18:29:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - discovery
  - evasion
  - obfuscation
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://h.43z.one/ipconverter/
  - https://twitter.com/Yasser_Elsnbary/status/1553804135354564608
  - https://twitter.com/fr0s7_/status/1712780207105404948
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_obfuscated_ip_download.yml
rules:
  - title: Obfuscated IP Address in PowerShell Download Command
    description: Detects PowerShell download commands containing hexadecimal or octal IP address representations
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - process_creation
      - windows
  - title: Obfuscated IP Address in curl Command
    description: Detects curl commands containing mixed encoding obfuscated IP addresses
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are increasingly using obfuscated IP addresses (e.g., hexadecimal, octal, or other encoded representations) within download commands to bypass security measures that rely on simple IP address blacklisting or pattern matching. This technique makes it more difficult to identify malicious network connections based on simple string matching. The observed commands include `Invoke-WebRequest`, `Invoke-RestMethod`, `wget`, `curl`, `DownloadFile`, and `DownloadString`. Defenders need to detect these obfuscated IPs to identify and block malicious download attempts. This technique has been observed across various attack campaigns and is a common tactic used to deliver malware while attempting to evade detection.

## Attack Chain

1.  An attacker gains initial access, potentially through phishing or exploiting a vulnerability.
2.  The attacker crafts a command containing an obfuscated IP address. This may involve converting a standard IP address into its hexadecimal, octal, or decimal representation.
3.  The attacker utilizes a command-line tool such as `curl`, `wget`, or PowerShell's `Invoke-WebRequest` to initiate a download. The command includes the obfuscated IP within a URL.
4.  The command interpreter resolves the obfuscated IP address back to its standard format before initiating the network connection.
5.  The target host establishes a connection to the attacker's server at the resolved IP address.
6.  The attacker's server delivers a malicious payload, such as a script, executable, or document containing macros.
7.  The downloaded payload is executed on the target system, potentially leading to further compromise, such as privilege escalation or lateral movement.
8.  The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or establishing persistent access.

## Impact

Successful exploitation can lead to the download and execution of malware, potentially compromising the targeted system. This can result in data breaches, system disruption, or financial loss. The use of obfuscation techniques makes it more difficult to detect and prevent these attacks, increasing the risk of successful compromise.

## Recommendation

*   Deploy the Sigma rule "Obfuscated IP Download Activity" to your SIEM to detect the use of obfuscated IP addresses in download commands. Tune the rule for your environment to minimize false positives.
*   Investigate any process creation events that match the Sigma rule, paying close attention to the command-line arguments.
*   Consider implementing additional network-based detection mechanisms to identify connections to suspicious IP addresses, even if they are obfuscated.
*   Monitor process creation logs (Sysmon) for processes executing download commands like `Invoke-WebRequest`, `Invoke-RestMethod`, `wget`, `curl`, `DownloadFile`, and `DownloadString` with suspicious arguments.
