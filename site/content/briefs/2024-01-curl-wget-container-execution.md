---
title: Curl or Wget Execution from Container Context
slug: 2024-01-curl-wget-container-execution
description: This rule detects the execution of curl or wget from within runc-backed containers on Linux systems monitored by Auditd Manager, indicating potential ingress tool transfer or data exfiltration by attackers who have compromised the container.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - execution
  - container
  - auditd
  - linux
vendors:
  - Elastic
products:
  - Auditd Manager
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://attack.mitre.org/techniques/T1105/
  - https://gtfobins.github.io/gtfobins/curl/
  - https://gtfobins.github.io/gtfobins/wget/
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/command_and_control_auditd_curl_wget_from_container.toml
rules:
  - title: Detect Curl or Wget Execution from Container Context
    description: Detects execution of curl or wget from processes with 'runc init' title, indicating potential container compromise.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1105
    data_sources:
      - process_creation
      - linux
  - title: Detect Curl or Wget Download Arguments in Container
    description: Detects curl or wget being used with arguments that suggest downloading files, within a container context.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1105
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection rule identifies instances of `curl` or `wget` being executed from within containers managed by `runc` on Linux systems. The rule leverages Auditd Manager to monitor system calls and flags processes running with the title `runc init` that then execute `curl` or `wget`. This activity is noteworthy because attackers often use these tools to download malicious payloads (stagers, scripts, implants) or to exfiltrate data after compromising a container. While these tools can be used legitimately within containers, their execution in the context of `runc init` suggests a higher risk of malicious activity. The rule focuses on narrowing the signal to the container runtime boundary where unexpected download clients are more worthy of review. The rule specifically leverages Auditd Manager for data collection.

## Attack Chain

1. An attacker gains initial access to a host system, possibly through exploiting a vulnerability in an application running outside the container (e.g., web application).
2. The attacker identifies a containerized application running on the compromised host.
3. The attacker exploits a vulnerability within the container, or abuses a privileged workload within the container, to gain elevated privileges or code execution within the container.
4. The attacker uses `curl` or `wget` to download additional tools or scripts into the container. These tools might include reverse shells, credential dumping tools, or data exfiltration utilities.
5. The attacker executes the downloaded tools to further compromise the container or the underlying host.
6. The attacker uses `curl` or `wget` to stage data for exfiltration to an external server. This may involve compressing and encoding data before transmission.
7. The attacker initiates the data exfiltration process using `curl` or `wget` to send the staged data to a remote server controlled by the attacker.
8. The attacker achieves their final objective, which could include data theft, system disruption, or further lateral movement within the network.

## Impact

Compromised containers can lead to data breaches, service disruptions, and further attacks on internal systems. Successful exploitation could allow attackers to steal sensitive data, install malware, or pivot to other parts of the network, impacting confidentiality, integrity, and availability. The number of affected systems depends on the scope of the container deployment and the privileges granted to the compromised container.

## Recommendation

*   Deploy the Sigma rule `Detect Curl or Wget Execution from Container Context` to your SIEM and tune for your environment.
*   Enable Auditd Manager with syscall coverage including `execve` to capture process execution and arguments within containers, as mentioned in the rule's setup instructions.
*   Correlate alerts from this rule with network logs to identify the destination IP addresses and domains contacted by the compromised container.
*   Baseline trusted images and exclude stable image digests or namespaces when noisy to reduce false positives, as suggested in the rule's false positives section.
