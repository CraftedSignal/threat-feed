---
title: Broadcom Patches Multiple Vulnerabilities in VMware Tanzu RabbitMQ on Kubernetes
slug: 2026-05-broadcom-rabbitmq-vulns
description: Broadcom published a security advisory addressing vulnerabilities in VMware Tanzu RabbitMQ on Kubernetes versions prior to 4.3.0, 4.2.6, 4.1.11, 4.0.20 and 3.13.15, potentially allowing an attacker to compromise the affected system.
date: "2026-05-11T17:38:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - patch
  - kubernetes
vendors:
  - Broadcom
products:
  - VMware Tanzu RabbitMQ on Kubernetes
references:
  - https://cyber.gc.ca/en/alerts-advisories/broadcom-vmware-security-advisory-av26-444
  - https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/37468
  - https://support.broadcom.com/web/ecx/security-advisory?segment=VT
rules:
  - title: Detect Kubernetes Pod Execution with Unusual Network Connections
    description: Detects Kubernetes pod execution with unusual network connections, potentially indicating lateral movement after a RabbitMQ compromise.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.006
    data_sources:
      - network_connection
      - linux
  - title: Detect Connection to Well-Known RabbitMQ Ports from Outside Kubernetes Cluster
    description: Detects network connections to well-known RabbitMQ ports (5671, 5672) originating from outside the Kubernetes cluster, potentially indicating unauthorized access attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1586.002
    data_sources:
      - network_connection
      - firewall
rules_count: 2
---

On May 8, 2026, Broadcom released a security advisory addressing vulnerabilities in VMware Tanzu RabbitMQ on Kubernetes. The advisory highlights the need for users and administrators to apply necessary updates to mitigate potential risks. VMware Tanzu RabbitMQ on Kubernetes is a messaging broker that allows applications to exchange data. Unpatched vulnerabilities in such systems could lead to various security incidents, including unauthorized access, data breaches, or service disruptions. The affected versions include those prior to 4.3.0, 4.2.6, 4.1.11, 4.0.20 and 3.13.15. Organizations utilizing these versions should prioritize reviewing and applying the provided updates to maintain a secure environment.

## Attack Chain

Given the lack of specific vulnerability details in the advisory, a generalized attack chain is presented based on common messaging service vulnerabilities:

1.  Initial Access: An attacker gains initial access to the Kubernetes cluster hosting Tanzu RabbitMQ, possibly through exposed API endpoints or compromised credentials.
2.  Discovery: The attacker identifies the vulnerable Tanzu RabbitMQ instance within the Kubernetes environment.
3.  Exploitation: The attacker exploits a vulnerability in Tanzu RabbitMQ, such as an authentication bypass or remote code execution flaw.
4.  Privilege Escalation: Leveraging the compromised RabbitMQ instance, the attacker escalates privileges within the Kubernetes cluster.
5.  Lateral Movement: The attacker moves laterally within the Kubernetes cluster, compromising other containers or pods.
6.  Data Exfiltration: The attacker exfiltrates sensitive data from the compromised Kubernetes environment.
7.  Persistence: The attacker establishes persistence within the Kubernetes cluster to maintain long-term access.
8.  Impact: The attacker achieves their final objective, such as data theft, service disruption, or further network compromise.

## Impact

Successful exploitation of these vulnerabilities in VMware Tanzu RabbitMQ on Kubernetes could lead to unauthorized access to sensitive data, service disruption, or complete compromise of the affected Kubernetes environment. The impact can vary depending on the specific vulnerability exploited and the attacker's objectives. Organizations running vulnerable versions of Tanzu RabbitMQ are at risk of data breaches, financial loss, and reputational damage.

## Recommendation

*   Review the Broadcom security advisory (https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/37468) to understand the specific vulnerabilities addressed.
*   Apply the necessary updates to VMware Tanzu RabbitMQ on Kubernetes to versions 4.3.0, 4.2.6, 4.1.11, 4.0.20, 3.13.15 or later as outlined in the Broadcom advisory.
*   Monitor network traffic for suspicious activity related to RabbitMQ, using a network intrusion detection system (NIDS).
*   Deploy the Sigma rule "Detect Kubernetes Pod Execution with Unusual Network Connections" to identify potential lateral movement after a compromise.
