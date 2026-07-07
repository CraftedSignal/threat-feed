---
title: Detection of Deprecated TLS Version or Weak Cipher Negotiated Externally
slug: 2026-07-deprecated-tls-weak-cipher
description: This rule identifies successful outbound TLS sessions initiated by internal hosts to external destinations that utilize deprecated protocol versions (SSLv3, TLS 1.0, TLS 1.1) or weak cipher suites such as RC4, 3DES, NULL, EXPORT, or anonymous Diffie-Hellman. Such negotiations can indicate an Adversary-in-the-Middle attack or communication with legacy malware, allowing for traffic interception or decryption. Detection engineers should investigate the `source.ip`, `destination.ip`, `tls.version`, and `tls.cipher` to determine if the destination is a legitimate legacy system or a potential compromise, checking for concurrent alerts on the source host.
date: "2026-07-05T01:52:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - network
  - tls
  - credential-access
  - command-and-control
  - mitm
  - downgrade
  - weak-cipher
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: Adversaries-in-the-middle and legacy malware often force these negotiations to decrypt or intercept traffic.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
    evidence: Legacy malware often force these negotiations to decrypt or intercept traffic.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1557/
  - https://www.elastic.co/docs/reference/integrations/network_traffic
  - https://www.elastic.co/docs/reference/ecs/ecs-tls
  - https://www.rfc-editor.org/rfc/rfc9325.html
rules:
  - title: Deprecated TLS Version or Weak Cipher Negotiated Externally
    description: Identifies successful outbound TLS sessions from internal hosts to external destinations that negotiate deprecated protocol versions (SSLv3, TLS 1.0, or TLS 1.1) or weak cipher suites. This can indicate Adversary-in-the-Middle attacks or legacy malware.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - credential_access
    techniques:
      - T1557
      - T1573
    data_sources:
      - network_connection
rules_count: 1
---

This brief details a detection for successful outbound TLS sessions that use deprecated protocol versions (SSLv3, TLS 1.0, TLS 1.1) or weak cipher suites, including RC4, 3DES, NULL, EXPORT, or anonymous Diffie-Hellman. Threat actors, specifically Adversaries-in-the-Middle (AitM), or legacy malware commonly force these weaker negotiations to facilitate traffic decryption or interception. Modern clients and services should ideally negotiate TLS 1.2 or 1.3 with strong ciphers for all internet-bound connections. The presence of such negotiations from internal hosts to external destinations is a strong indicator of potential compromise, a configured MITM appliance, or communication with outdated and insecure endpoints. This detection is crucial for identifying potential credential access or command and control (C2) activity that relies on exploiting these cryptographic weaknesses.

## Attack Chain

1.  **Initial Compromise / Positioning**: Adversary gains initial access to the internal network (e.g., via phishing, vulnerability exploitation) or positions themselves strategically to conduct a Man-in-the-Middle (MITM) attack on network segments.
2.  **Network Interception / Malware Deployment**: The attacker either intercepts network traffic directly (MITM) or deploys legacy malware onto an internal host that initiates outbound network connections.
3.  **TLS Session Initiation**: An internal host attempts to establish an outbound TLS session to an external destination, often for legitimate communication purposes.
4.  **Forced Downgrade / Weak Cipher Negotiation**: The adversary (in a MITM position) or the legacy malware manipulates the TLS handshake process, forcing the client and/or server to negotiate a deprecated TLS protocol version (SSLv3, TLS 1.0, TLS 1.1) or a weak cipher suite (RC4, 3DES, NULL, EXPORT, anonymous Diffie-Hellman).
5.  **Successful Weak Negotiation**: The TLS handshake successfully completes, establishing an encrypted channel using the outdated protocol or weak cipher suite, making the traffic susceptible to decryption.
6.  **Traffic Interception/Decryption**: With the weaker encryption, the adversary can now intercept and decrypt the traffic flowing over the compromised TLS session, gaining access to sensitive data such as credentials or proprietary information.
7.  **Credential Access / Command and Control**: The decrypted information is leveraged for credential harvesting and lateral movement, or the weak TLS channel is utilized by malware for resilient command and control (C2) communications with attacker infrastructure.

## Impact

Successful exploitation or utilization of deprecated TLS versions and weak ciphers by adversaries can lead to significant impact, primarily through the compromise of data confidentiality and integrity. Attackers can intercept and decrypt sensitive information, including user credentials, proprietary business data, and intellectual property, transiting over the network. This can result in unauthorized access to systems and services, data exfiltration, and a loss of trust in communications. While the brief does not specify victim counts, any organization with internal hosts communicating externally via these weak protocols is vulnerable to potential data breach and compromise, particularly within sectors handling sensitive data or operating critical infrastructure.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect deprecated TLS versions and weak cipher negotiations.
*   Ensure your network traffic logging (`network_traffic.tls` data stream, or equivalent) is configured to capture TLS metadata, including `tls.version`, `tls.version_protocol`, `tls.cipher`, and `tls.established`.
*   Investigate all alerts generated by the "Deprecated TLS Version or Weak Cipher Negotiated Externally" rule, examining `source.ip`, `destination.ip`, `destination.port`, `tls.version`, and `tls.cipher` to differentiate between legitimate legacy systems and malicious activity.
*   Establish baselines for known legacy internal applications, industrial control systems, or embedded devices that legitimately require deprecated TLS, and create exclusions after validation to reduce false positives.
*   Implement and enforce TLS 1.2 or higher as the minimum acceptable version on all egress proxies and network gateways, and inspect for MITM appliances that might be forcing weak negotiation.
*   Block or proxy traffic to external destinations identified as engaging in suspicious weak TLS negotiations if the activity appears attacker-driven.
*   Patch or replace client and server applications/systems identified as negotiating deprecated TLS versions or weak ciphers to enforce stronger cryptographic standards.
