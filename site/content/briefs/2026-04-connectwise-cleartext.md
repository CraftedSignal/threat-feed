---
title: ConnectWise Automate Solution Center Cleartext Communication Vulnerability (CVE-2026-6066)
slug: 2026-04-connectwise-cleartext
description: ConnectWise Automate is vulnerable to CVE-2026-6066, a cleartext transmission of sensitive information vulnerability, where certain client-to-server communications could occur without transport-layer encryption, potentially allowing network-based interception of Solution Center traffic, and the issue is resolved in Automate 2026.4 by enforcing secure communication.
date: "2026-04-21T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - cve-2026-6066
  - connectwise
  - cleartext
  - rmm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-6066
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6066
  - https://www.connectwise.com/company/trust/security-bulletins/2026-04-20-connectwise-automate-bulletin
iocs:
  - type: url
    value: https://www.connectwise.com/company/trust/security-bulletins/2026-04-20-connectwise-automate-bulletin
ioc_counts:
  url: 1
rules:
  - title: Detect Unencrypted ConnectWise Automate Communication
    description: Detects network traffic potentially related to unencrypted ConnectWise Automate Solution Center communication by looking for connections to port 443 without TLS negotiation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1071.001
      - T1566
    data_sources:
      - network_connection
      - windows
  - title: Detect ConnectWise Automate Process Initiating Network Connection
    description: Detects ConnectWise Automate process making network connections which may indicate data exfiltration or command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

ConnectWise Automate is a remote monitoring and management (RMM) platform used by managed service providers (MSPs). CVE-2026-6066 describes a vulnerability in the ConnectWise Automate Solution Center where specific client-to-server communications may occur without transport-layer encryption. An attacker positioned on the network could intercept sensitive data transmitted in cleartext. This vulnerability was disclosed on April 20, 2026, and affects ConnectWise Automate versions prior to 2026.4. Successful exploitation allows an attacker to potentially gain access to credentials, configuration details, and other sensitive information related to the managed clients. The vulnerability has been resolved in Automate 2026.4 by enforcing secure communication for affected Solution Center connections.

## Attack Chain

1. Attacker gains network access to a ConnectWise Automate deployment.
2. Attacker passively monitors network traffic for communications between Automate clients and the Solution Center.
3. Attacker identifies vulnerable client-to-server communications occurring without transport-layer encryption.
4. Attacker intercepts the cleartext network traffic using a packet capture tool such as Wireshark or tcpdump.
5. Attacker analyzes the intercepted traffic to identify sensitive information such as credentials or configuration data.
6. Attacker uses the acquired credentials to gain unauthorized access to managed systems or customer environments.
7. Attacker leverages compromised systems for lateral movement within the network.

## Impact

Successful exploitation of CVE-2026-6066 can lead to the compromise of ConnectWise Automate deployments, potentially affecting hundreds or thousands of MSP clients. An attacker could intercept credentials, configuration data, and other sensitive information, leading to unauthorized access to managed systems. This could result in data breaches, ransomware attacks, and other malicious activities targeting MSP clients. The severity is amplified by the widespread use of ConnectWise Automate among MSPs and the potential for cascading effects across their customer base.

## Recommendation

*   Upgrade ConnectWise Automate to version 2026.4 or later to remediate CVE-2026-6066 as per the ConnectWise security bulletin ([https://www.connectwise.com/company/trust/security-bulletins/2026-04-20-connectwise-automate-bulletin](https://www.connectwise.com/company/trust/security-bulletins/2026-04-20-connectwise-automate-bulletin)).
*   Implement network segmentation and monitoring to detect and prevent unauthorized network access and traffic interception.
*   Deploy the Sigma rule for unencrypted ConnectWise Automate communication to identify potentially vulnerable connections.
*   Review and enforce strong password policies and multi-factor authentication for all ConnectWise Automate accounts.
