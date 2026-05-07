---
title: Broadcom Patches Multiple Vulnerabilities in Tanzu Products
slug: 2026-05-broadcom-tanzu
description: Broadcom released security advisories on May 7, 2026, addressing vulnerabilities in several Tanzu products, requiring users and administrators to apply necessary updates to mitigate potential risks.
date: "2026-05-07T15:30:27Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - vulnerability
  - patch
  - broadcom
  - tanzu
vendors:
  - Broadcom
products:
  - Tanzu Greenplum Command Center
  - Tanzu Greenplum Data Copy Utility
  - Tanzu for MySQL on Kubernetes
  - Tanzu Greenplum Streaming Server for Kubernetes
  - Tanzu Greenplum Streaming Server
  - Tanzu Greenplum Streaming on Kubernetes
  - Tanzu Greenplum Text
  - Tanzu for Valkey on Kubernetes
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://cyber.gc.ca/en/alerts-advisories/broadcom-vmware-security-advisory-av26-434
  - https://support.broadcom.com/web/ecx/security-advisory?segment=VT
rules:
  - title: Detect Suspicious Process Execution in Kubernetes Pods
    description: Detects suspicious process execution within Kubernetes pods, which could indicate exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Outbound Network Connection from Kubernetes Pod to External IP
    description: Detects outbound network connections from Kubernetes pods to external IP addresses, potentially indicating command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

On May 7, 2026, Broadcom released security advisories addressing vulnerabilities in its Tanzu product line. These advisories detail critical updates for multiple Tanzu components, including Greenplum Command Center (versions prior to 6.17.0 and 7.7.0), Data Copy Utility (versions prior to 2.9.3), MySQL on Kubernetes (versions prior to 2.0.3), Streaming Server (versions prior to 2.3.0) and its Kubernetes variant (versions prior to 1.3.0 and 1.1.0), Text (versions prior to 4.0.0), and Valkey on Kubernetes (versions prior to 3.3.4 and 3.4.0). The vulnerabilities, if exploited, could lead to unauthorized access, data breaches, or service disruption. It is critical for organizations using these Tanzu products to apply the provided patches to prevent potential exploitation. The advisories specifically target outdated versions, highlighting the importance of maintaining up-to-date software environments.

## Attack Chain

Given the lack of specific vulnerability details, the following is a generalized attack chain based on typical software vulnerabilities that these patches likely address:

1. **Initial Access:** An attacker identifies a vulnerable Tanzu component accessible over the network, potentially through exposed APIs or web interfaces.
2. **Vulnerability Exploitation:** The attacker leverages a known vulnerability (e.g., remote code execution, SQL injection) to gain unauthorized access.
3. **Privilege Escalation:** Once initial access is gained, the attacker attempts to escalate privileges within the compromised Tanzu environment.
4. **Lateral Movement:** The attacker uses the compromised system to move laterally to other systems within the Kubernetes cluster or broader network.
5. **Data Access:** The attacker accesses sensitive data managed by the Tanzu components, such as database credentials, application configurations, or user data.
6. **Persistence:** The attacker establishes persistence mechanisms (e.g., backdoors, rogue containers) to maintain access to the compromised environment.
7. **Exfiltration / Impact:** The attacker exfiltrates sensitive data or performs other malicious activities, such as data manipulation, denial-of-service attacks, or deployment of ransomware.

## Impact

Successful exploitation of these vulnerabilities could result in significant damage. This includes unauthorized access to sensitive data, potential data breaches, disruption of critical services, and lateral movement to other systems within the network. The exact number of victims and sectors targeted is currently unknown, but given the widespread use of Tanzu products, the potential impact is substantial. Failure to apply these patches could lead to severe operational and financial consequences for affected organizations.

## Recommendation

*   Review the Broadcom security advisories for Tanzu products immediately and identify vulnerable systems. Reference: [Security Advisories Tanzu](https://support.broadcom.com/web/ecx/security-advisory?segment=VT)
*   Apply the necessary updates to Tanzu Greenplum Command Center, Data Copy Utility, MySQL on Kubernetes, Streaming Server (for Kubernetes and standalone), Streaming on Kubernetes, Text, and Valkey on Kubernetes to address the vulnerabilities.
*   Deploy the Sigma rule below to detect suspicious process execution within Kubernetes environments related to potential exploitation attempts.
*   Continuously monitor network traffic for unusual activity originating from Tanzu components, which may indicate ongoing exploitation.
