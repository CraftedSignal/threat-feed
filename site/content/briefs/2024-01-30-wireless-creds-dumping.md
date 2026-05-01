---
title: Wireless Credential Dumping via Netsh
slug: 2024-01-30-wireless-creds-dumping
description: Adversaries use the Windows built-in utility Netsh to dump Wireless saved access keys in clear text, potentially leading to credential compromise.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - netsh
  - windows
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Defender XDR
  - Elastic Defend
  - Sysmon
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
references:
  - https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts
  - https://www.geeksforgeeks.org/how-to-find-the-wi-fi-password-using-cmd-in-windows/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_wireless_creds_dumping.toml
rules:
  - title: Detect Wireless Credential Dumping via Netsh
    description: Detects attempts to dump wireless credentials using the netsh command with 'wlan' and 'key=clear' arguments.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
  - title: Detect Netsh WLAN Profile Enumeration
    description: Detects the use of netsh to enumerate WLAN profiles, which is often a precursor to credential dumping.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1003
      - T1016
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers often target wireless credentials to gain unauthorized network access. This involves using the legitimate Windows command-line tool `netsh.exe` to extract Wi-Fi passwords stored on a compromised system. By leveraging `netsh`, attackers can bypass traditional security measures and retrieve sensitive information without deploying custom malware. The technique involves specific command-line arguments that instruct `netsh` to display wireless keys in cleartext, exposing the network passwords. Defenders must monitor `netsh` command-line activity to identify potential credential access attempts. This activity can lead to lateral movement within the network.

## Attack Chain

1.  The attacker gains initial access to a Windows system (e.g., via phishing or exploiting a software vulnerability).
2.  The attacker executes `netsh.exe` with specific arguments to list available wireless profiles.
3.  The attacker identifies a target wireless profile from the list.
4.  The attacker executes `netsh.exe` again, this time specifying the target profile and requesting the key to be displayed in cleartext using the `key=clear` argument.
5.  `Netsh.exe` retrieves the Wi-Fi password from the Windows Wireless LAN service.
6.  The password is displayed in the command output, which the attacker captures.
7.  The attacker uses the obtained Wi-Fi password to connect to the wireless network.
8.  The attacker can now perform lateral movement and access internal resources.

## Impact

Successful credential dumping allows attackers to gain unauthorized access to wireless networks. This can lead to lateral movement within the organization's network, access to sensitive data, and further compromise of systems and resources. The impact includes potential data breaches, financial losses, and reputational damage. This technique allows attackers to bypass traditional network access controls.

## Recommendation

*   Deploy the Sigma rule `Detect Wireless Credential Dumping via Netsh` to identify suspicious `netsh.exe` commands in your environment.
*   Enable Sysmon process creation logging to capture the `netsh.exe` command-line arguments.
*   Investigate any alerts triggered by the Sigma rule, focusing on the process lineage and user context as outlined in the "Triage and analysis" section of the source.
*   Implement strong password policies for Wi-Fi networks, including the use of WPA2 or WPA3 encryption.
*   Review and restrict the use of `netsh.exe` on systems where it is not required, using application control solutions.
*   Monitor for related alerts indicating lateral movement, staging, remote access, or persistence, as mentioned in the "Triage and analysis" section of the source.
