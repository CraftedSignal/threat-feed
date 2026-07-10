---
title: Wireless Credential Dumping using Netsh Command
slug: 2024-01-25-netsh-wireless-creds-dump
description: Attackers may attempt to dump wireless credentials using `netsh.exe` to gain unauthorized network access, potentially leading to lateral movement and data compromise.
date: "2024-01-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - discovery
  - windows
  - netsh
  - wireless
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
references:
  - https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts
  - https://www.geeksforgeeks.org/how-to-find-the-wi-fi-password-using-cmd-in-windows/
rules:
  - title: Detect Wireless Credential Dumping via Netsh
    description: Detects the execution of netsh.exe with arguments indicative of dumping wireless network credentials in clear text.
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
    description: Detects the execution of netsh.exe to enumerate wireless profiles, which often precedes credential dumping attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the abuse of `netsh.exe`, a legitimate Windows command-line utility, to dump wireless network credentials in clear text. Attackers can exploit this to gain unauthorized access to wireless networks, potentially facilitating lateral movement and data theft. The activity is detected by monitoring process executions for `netsh.exe` with specific command-line arguments related to wireless LAN (WLAN) profiles and key extraction in clear text. This technique can be employed by both external attackers and malicious insiders to compromise network security. The goal is to obtain saved Wi-Fi passwords, enabling unauthorized network access. This activity can be part of a broader attack campaign, starting from initial access and escalating to sensitive data exfiltration.

## Attack Chain

1.  The attacker gains initial access to a compromised Windows host.
2.  The attacker executes `netsh.exe` with specific arguments to list available WLAN profiles: `netsh wlan show profiles`.
3.  The attacker uses `netsh.exe` to dump the wireless key in clear text for a specific profile: `netsh wlan show profile name="<profile_name>" key=clear`.
4.  The command output reveals the clear text password for the targeted Wi-Fi network.
5.  The attacker uses the stolen Wi-Fi credentials to connect to the wireless network.
6.  Once connected, the attacker performs network reconnaissance to identify valuable targets and resources.
7.  The attacker moves laterally through the network, exploiting vulnerabilities or misconfigurations to compromise additional systems.
8.  The final objective could include data exfiltration, installation of backdoors, or ransomware deployment.

## Impact

Successful exploitation allows unauthorized access to wireless networks, bypassing traditional security measures. This can lead to lateral movement within the network, enabling attackers to access sensitive data, compromise critical systems, and potentially deploy ransomware. The impact ranges from data breaches and financial losses to reputational damage and disruption of services. The severity depends on the sensitivity of the data accessible through the compromised network and the attacker's subsequent actions.

## Recommendation

*   Deploy the Sigma rule `Detect Wireless Credential Dumping via Netsh` to identify malicious use of `netsh.exe` (see "rules" section).
*   Enable Sysmon process-creation logging (Event ID 1) to enhance visibility into command-line arguments of executed processes.
*   Implement strict access controls and the principle of least privilege to minimize the impact of credential theft.
*   Regularly review and update wireless network configurations and passwords to prevent unauthorized access using old credentials.
*   Monitor for suspicious network connections originating from systems that have executed `netsh.exe` with WLAN-related arguments.
