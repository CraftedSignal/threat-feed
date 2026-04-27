---
title: ConnectWise Automate Solution Center Cleartext Communication Vulnerability (CVE-2026-6066)
slug: 2026-04-connectwise-cleartext
description: ConnectWise Automate is vulnerable to CVE-2026-6066, a cleartext transmission of sensitive information vulnerability, where certain client-to-server communications could occur without transport-layer encryption, potentially allowing network-based interception of Solution Center traffic, and the issue is resolved in Automate 2026.4 by enforcing secure communication.
date: "2026-04-21T12:00:00Z"
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

ConnectWise Automate is a remote monitoring and management (RMM) platform used by managed service providers (MSPs). CVE-2026-6066 describes a vulnerability in the ConnectWise Automate Solution Center where specific client-to-server communications may occur without transport-layer encryption. An attacker positioned on the network could intercept sensitive data transmitted in cleartext. This vulnerability was disclosed on April 20, 2026, and affects ConnectWise Automate versions prior to 2026.4…
