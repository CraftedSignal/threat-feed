---
title: LOLBIN Network Connection for Defense Evasion
slug: 2024-01-lolbin-network-connection
description: Adversaries can use Living-Off-The-Land Binaries (LOLBINs) such as expand.exe, extrac32.exe, ieexec.exe, and makecab.exe to establish network connections, potentially bypassing security controls and facilitating malicious activities on Windows systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - lolbin
  - defense-evasion
  - windows
vendors:
  - Elastic
products:
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - Sysmon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  - https://attack.mitre.org/techniques/T1218/
rules:
  - title: Network Connection via Signed Binary
    description: Detects network connections initiated by specific Windows LOLBINs (expand.exe, extrac32.exe, ieexec.exe, makecab.exe) excluding connections to private IP ranges.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - network_connection
      - windows
  - title: Process Execution of LOLBINs
    description: Detects execution of LOLBINs used for defense evasion.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may leverage LOLBINs, signed binaries that are part of the operating system, to perform malicious actions while blending in with legitimate system activity. This technique allows them to evade detection by application allowlists and signature validation. This brief focuses on the abuse of expand.exe, extrac32.exe, ieexec.exe, and makecab.exe to initiate outbound network connections. The LOLBINs are used to execute malicious code, download additional payloads, or establish command and control channels. This activity can be indicative of malware installation, data exfiltration, or other malicious post-exploitation activities. Detection is crucial to identify potentially compromised systems and prevent further damage.

## Attack Chain

1.  An attacker gains initial access to the target system (e.g., through phishing or exploitation of a vulnerability).
2.  The attacker executes a signed LOLBIN, such as `expand.exe`, `extrac32.exe`, `ieexec.exe`, or `makecab.exe`.
3.  The LOLBIN is used to download or execute a malicious payload from a remote server.
4.  The executed binary establishes a network connection to an external IP address.
5.  Data exfiltration may occur over the established network connection.
6.  The attacker maintains persistence on the system by scheduling tasks or modifying registry keys.
7.  The attacker moves laterally within the network, compromising additional systems.

## Impact

A successful attack leveraging LOLBINs can result in the installation of malware, data theft, or full system compromise. The use of signed binaries makes it more difficult to detect malicious activity, potentially allowing attackers to operate undetected for extended periods. The financial and reputational damage caused by such attacks can be significant. While the risk score is low, the potential for defense evasion justifies monitoring.

## Recommendation

*   Implement the provided Sigma rule `Network Connection via Signed Binary` to detect suspicious network connections initiated by LOLBINs.
*   Monitor process execution logs for instances of `expand.exe`, `extrac32.exe`, `ieexec.exe`, and `makecab.exe` using process creation logging.
*   Review network connection logs for outbound connections initiated by these processes, excluding connections to internal networks based on the provided list of private IP ranges.
*   Investigate any detected instances of LOLBINs making external network connections, correlating with other suspicious activities on the affected host, as detailed in the "Triage and analysis" section.
