---
title: Linux Iptables Firewall Modification Detection
slug: 2024-01-linux-iptables-modification
description: This brief details a Splunk search that identifies suspicious command-line activity modifying iptables firewall settings on Linux systems, potentially indicating Cyclops Blink malware activity allowing C2 communication by opening specific TCP ports.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Sandworm Tools
tags:
  - iptables
  - firewall
  - linux
  - cyclopsblink
vendors:
  - ASUS
products:
  - ASUS routers
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.ncsc.gov.uk/files/Cyclops-Blink-Malware-Analysis-Report.pdf
  - https://www.trendmicro.com/en_us/research/22/c/cyclops-blink-sets-sights-on-asus-routers--.html
rules:
  - title: Linux Iptables Firewall Modification
    description: Detects suspicious command-line activity that modifies the iptables firewall settings on a Linux machine.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - process_creation
      - linux
  - title: Linux Iptables Specific Port Modification
    description: Detects iptables modifications opening specific ports associated with potential Cyclops Blink activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection focuses on identifying malicious modifications to iptables firewall settings on Linux systems. The activity is associated with malware such as Cyclops Blink, known to alter firewall rules to facilitate Command and Control (C2) communication. The Splunk search analyzes process command lines, looking for iptables commands that open specific TCP ports (3269, 636, 989, 994, 995, 8443). The detection logic filters out common legitimate parent process paths to reduce false positives. Successful exploitation can lead to persistent access and data exfiltration. The original Splunk search was published on 2026-05-05.

## Attack Chain

1.  The attacker gains initial access to the Linux system, possibly through exploiting a vulnerability or using stolen credentials.
2.  The attacker or malware executes a command to modify the iptables firewall settings.
3.  The iptables command uses the `--dport` flag to specify a TCP port to open (e.g., 3269, 636, 989, 994, 995, 8443).
4.  The command includes the `ACCEPT` action, allowing traffic to the specified port.
5.  The command redirects output to `/dev/null` to hide the activity.
6.  The modified iptables rules allow inbound traffic on the opened port(s).
7.  The attacker uses the opened port(s) for C2 communication with the compromised system.
8.  The attacker maintains persistent access and potentially exfiltrates sensitive data.

## Impact

Successful modification of iptables can expose internal services to external attackers, facilitating unauthorized access, data exfiltration, and further compromise of the affected system. Cyclops Blink malware targets ASUS routers, allowing attackers to gain control over network devices and potentially pivot to other systems on the network. The number of affected devices can range from a few to thousands depending on the scope of the attack.

## Recommendation

*   Deploy the Sigma rule `Linux Iptables Firewall Modification` to your SIEM and tune for your environment.
*   Investigate any alerts triggered by the `Linux Iptables Firewall Modification` rule, focusing on unusual parent processes and destination systems.
*   Review the references provided, specifically the NCSC report and Trend Micro analysis on Cyclops Blink, for additional context and IOCs.
*   Monitor systems for network connections to the opened ports (3269, 636, 989, 994, 995, 8443) as identified in the rule logic.
