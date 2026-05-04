---
title: Mshta Making Network Connections Indicative of Defense Evasion
slug: 2024-01-mshta-network-connections
description: Mshta.exe making outbound network connections may indicate adversarial activity, as it is often used to execute malicious scripts and evade detection by proxying execution of untrusted code.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - system-binary-proxy-execution
  - windows
vendors:
  - Microsoft
  - Amazon
  - TeamViewer
  - SentinelOne
  - Elastic
products:
  - Amazon Assistant
  - TeamViewer
  - Elastic Defend
  - SentinelOne Cloud Funnel
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/005/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Mshta.exe Making Network Connections
    description: Detects Mshta.exe making outbound network connections, which may indicate adversarial activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.005
    data_sources:
      - network_connection
      - windows
  - title: Mshta Executing Script from Suspicious Location
    description: Detects Mshta.exe executing scripts from unusual directories, which may indicate malicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Mshta.exe is a legitimate Windows utility used to execute Microsoft HTML Application (HTA) files. Adversaries exploit it to run malicious scripts, leveraging its trusted status to bypass security measures. This activity can be difficult to detect because Mshta.exe is a signed Microsoft binary. This detection identifies suspicious network activity by Mshta.exe, excluding known benign processes, to flag potential threats. Legitimate uses of Mshta.exe include software updates, installations, and automation scripts using HTA files. This rule helps identify unauthorized network connections indicative of malicious intent and flags suspicious use of mshta.exe.

## Attack Chain

1. An attacker gains initial access through an unknown method, such as phishing or exploiting a software vulnerability.
2. The attacker executes a malicious script, such as VBScript or JavaScript, using Mshta.exe.
3. Mshta.exe interprets and executes the script, bypassing application control policies due to its signed status.
4. The script establishes a network connection to an external command and control (C2) server.
5. The C2 server provides instructions to the compromised host, such as downloading additional malware.
6. The downloaded malware executes, performing actions such as data exfiltration or lateral movement.
7. The attacker leverages the compromised host to move laterally within the network, compromising additional systems.
8. The attacker achieves their objective, such as stealing sensitive data or deploying ransomware.

## Impact

Successful exploitation can lead to the execution of arbitrary code, potentially compromising sensitive data, facilitating lateral movement, and establishing a persistent presence within the network. Systems affected by this activity may be used as a beachhead for further attacks, leading to significant data breaches, financial loss, and reputational damage. The number of victims can vary depending on the scope of the initial compromise and the attacker's objectives.

## Recommendation

*   Enable Sysmon process creation logging to capture the command-line arguments used by Mshta.exe.
*   Deploy the "Mshta Network Connection" Sigma rule to your SIEM and tune for your environment.
*   Implement application whitelisting to prevent unauthorized execution of Mshta.exe and similar system binaries.
*   Monitor network connections initiated by Mshta.exe, including destination IP addresses, domains, and ports, to identify any connections to known malicious or suspicious endpoints.
