---
brief_id: brief-2024-01-02-rpc-internet-access
event_id: brief-2024-01-02-rpc-internet-access
revision: 2
activity_at: "2024-01-02T12:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:34b4f0e260e9b6e7763df842097cba4003c75ce56a9c97e15d3a184d8d9977d4
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Detecting RPC Traffic from the Internet
slug: 2024-01-02-rpc-internet-access
description: This rule detects network events that may indicate the use of RPC traffic from the Internet, which is commonly targeted and exploited by threat actors as an initial access or backdoor vector.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - network_traffic
  - initial_access
  - rpc
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  - https://attack.mitre.org/techniques/T1190/
rules:
  - title: Detect RPC traffic from the Internet
    description: Detects network traffic indicative of RPC (Remote Procedure Call) communication originating from the Internet, which may indicate unauthorized access attempts or exploitation of vulnerable services.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect RPC traffic from the Internet - Linux
    description: Detects network traffic indicative of RPC (Remote Procedure Call) communication originating from the Internet, which may indicate unauthorized access attempts or exploitation of vulnerable services.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

This detection rule identifies network events indicative of RPC (Remote Procedure Call) traffic originating from the Internet. RPC, designed for remote system management and resource sharing, should not be directly exposed to the internet. Threat actors frequently target exposed RPC services as an initial access or backdoor vector, making this traffic a significant security risk. The rule focuses on detecting TCP port 135, commonly associated with RPC, while filtering out internal IP addresses to minimize false positives. The rule aims to detect RPC communication from external sources to internal networks.

## Attack Chain

1. An attacker identifies a public-facing server with an open TCP port 135 (RPC endpoint).
2. The attacker initiates a TCP connection to the target server's port 135.
3. The attacker sends RPC requests to the server, attempting to enumerate available services and identify vulnerabilities.
4. The server responds to the RPC requests, providing information about available services.
5. The attacker exploits a known vulnerability in one of the RPC services, such as a buffer overflow or authentication bypass (T1190).
6. Upon successful exploitation, the attacker gains initial access to the server.
7. The attacker uses the compromised server as a pivot point to move laterally within the internal network.
8. The attacker attempts to gain access to sensitive data or critical systems, potentially leading to data theft or system compromise.

## Impact

Exposure of RPC services to the Internet can lead to unauthorized access to internal systems. A successful attack can compromise sensitive data, disrupt critical services, and facilitate lateral movement within the network. The impact ranges from data breaches and financial loss to complete system compromise, depending on the attacker's objectives and the extent of the vulnerability.

## Recommendation

*   Deploy the Sigma rule "Detect RPC traffic from the Internet" to your SIEM and tune it to your environment by adjusting the excluded internal IP ranges.
*   Review network configurations and firewall rules to ensure that RPC services are not exposed to the Internet.
*   Implement network segmentation to limit the exposure of critical systems and services.
*   Investigate and patch any identified vulnerabilities in RPC services, focusing on CVEs related to remote code execution (T1190).
*   Enable and review network traffic logs to identify any suspicious activity related to RPC traffic.
