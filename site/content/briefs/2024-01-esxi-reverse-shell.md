---
title: ESXi Host Reverse Shell Detection
slug: 2024-01-esxi-reverse-shell
description: This detection identifies reverse shell string patterns on an ESXi host via syslog, potentially indicating a threat actor attempting to establish remote control over the system, which may lead to further compromise such as ransomware deployment.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - esxi
  - reverse-shell
  - vmware
  - syslog
  - ransomware
vendors:
  - VMware
products:
  - ESXi
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/splunk/security_content/blob/main/detections/application/esxi_reverse_shell_patterns.yml
rules:
  - title: ESXi Reverse Shell via Bash
    description: Detects reverse shell attempts on ESXi hosts using bash.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - syslog
      - vmware
  - title: ESXi Reverse Shell via Python Socket
    description: Detects reverse shell attempts on ESXi hosts using Python's socket module.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.005
    data_sources:
      - syslog
      - vmware
  - title: ESXi Reverse Shell via Netcat
    description: Detects reverse shell attempts on ESXi hosts using Netcat.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - syslog
      - vmware
rules_count: 3
---

This brief focuses on detecting reverse shell attempts on VMware ESXi hosts. The detection is triggered by specific command patterns within ESXi syslog data indicative of an attacker attempting to establish remote access. The patterns include `bash -i >&`, `/dev/tcp`, `/dev/udp`, `socat exec`, and `python -c import socket`. Successfully establishing a reverse shell allows an attacker to execute commands, move laterally within the network, and potentially deploy ransomware such as Black Basta, as indicated by its presence in related analytic stories. The monitoring of ESXi hosts is crucial due to their central role in virtualized environments.

## Attack Chain

1.  The attacker gains initial access to the ESXi host, possibly through exploiting a known vulnerability or using stolen credentials.
2.  The attacker attempts to execute a reverse shell command, embedding it within a seemingly benign process or script. Example commands include those using bash, netcat (`/dev/tcp`, `/dev/udp`), socat, or Python's `socket` module.
3.  The ESXi host logs the reverse shell command within its syslog.
4.  The attacker's reverse shell command attempts to establish a TCP or UDP connection back to the attacker-controlled server.
5.  The attacker uses the reverse shell to execute commands on the ESXi host, potentially escalating privileges.
6.  The attacker leverages their access to gather information about the virtual environment, including the configuration and location of virtual machines.
7.  The attacker uses their gained access to laterally move to other systems within the network, including guest VMs.
8.  The final objective could involve deploying ransomware on the guest VMs or exfiltrating sensitive data.

## Impact

A successful reverse shell attack on an ESXi host can lead to complete compromise of the virtualized environment. This includes the potential for data theft, disruption of services, and deployment of ransomware on multiple virtual machines. ESXi compromises are often associated with ransomware campaigns like Black Basta, impacting numerous organizations across various sectors. The severity stems from the centralized role of ESXi in managing virtual infrastructure.

## Recommendation

*   Configure ESXi hosts to forward syslog output to a central logging server for analysis (VMWare ESXi Syslog data source).
*   Deploy the Sigma rules provided in this brief to your SIEM and tune them to reduce false positives in your environment.
*   Review and harden ESXi host access controls and patch management procedures to prevent initial access.
*   Investigate any alerts triggered by the Sigma rules, focusing on the `dest` field (destination IP/hostname) to identify the attacker's target.
*   Monitor network connections originating from ESXi hosts, specifically looking for unusual outbound traffic patterns (network_connection log source).
