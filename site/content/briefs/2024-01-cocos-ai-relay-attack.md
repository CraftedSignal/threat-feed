---
title: Cocos AI Attested TLS Relay Attack Vulnerability (CVE-2026-33697)
slug: 2024-01-cocos-ai-relay-attack
description: A relay attack vulnerability, tracked as CVE-2026-33697, exists in the attested TLS (aTLS) implementation of Cocos AI, versions v0.4.0 through v0.8.2, allowing attackers to impersonate a legitimate service and potentially access sensitive data.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - relay attack
  - attested TLS
  - Cocos AI
vendors:
  - Cocos AI
products:
  - Cocos AI
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33697
rules:
  - title: Detect Cocos AI Attested TLS Session Hijacking (Network)
    description: Detects potential hijacking of Cocos AI attested TLS sessions by monitoring for unusual network connections to Cocos AI servers after initial TLS handshake.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.006
    data_sources:
      - network_connection
      - zeek
  - title: Detect Cocos AI Ephemeral Key File Access
    description: Detects potential exfiltration of ephemeral TLS keys by monitoring file access events related to key files within Cocos AI directories.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.006
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Cocos AI is a confidential computing system for AI that utilizes attested TLS (aTLS). A critical relay attack vulnerability, identified as CVE-2026-33697, has been discovered in the aTLS implementation affecting versions v0.4.0 through v0.8.2. This vulnerability impacts both AMD SEV-SNP and Intel TDX deployment targets. An attacker who successfully extracts the ephemeral TLS private key during the handshake can relay or divert the attested TLS session. This allows the attacker to impersonate a genuine CoCoS service, potentially gaining unauthorized access to data or operations intended for the legitimate endpoint. Exploitation necessitates extracting the ephemeral TLS private key, achievable through physical access to the server hardware, transient execution attacks, or side-channel attacks. The aTLS implementation was redesigned in v0.7.0, but this redesign did not address the underlying architectural vulnerability. Currently, there is no patch available or complete workaround, posing a significant risk to deployments of Cocos AI.

## Attack Chain

1. **Initial Compromise:** The attacker gains physical access to the server hardware or leverages transient execution attacks or side-channel attacks to target the Cocos AI environment.
2. **Ephemeral Key Extraction:** The attacker successfully extracts the ephemeral TLS private key used during the aTLS handshake process.
3. **TLS Session Interception:** The attacker intercepts the initial TLS handshake between a client and a legitimate Cocos AI service.
4. **Relay/Divert Attestation:** Using the extracted ephemeral key, the attacker relays or diverts the attested TLS session to a malicious endpoint controlled by the attacker.
5. **Impersonation:** The attacker's malicious endpoint presents the stolen attestation evidence to the client, impersonating the legitimate Cocos AI service.
6. **Client Connection:** The client, falsely believing it is communicating with the genuine service, establishes a connection with the attacker's endpoint.
7. **Data Exfiltration/Manipulation:** The attacker gains unauthorized access to data or operations intended for the legitimate service, potentially exfiltrating sensitive information or manipulating AI processes.
8. **Maintain Persistence:** The attacker may attempt to maintain a persistent presence within the compromised environment for continued access or further exploitation.

## Impact

Successful exploitation of CVE-2026-33697 allows an attacker to impersonate an attested Cocos AI service, potentially leading to unauthorized access to sensitive data and critical AI operations. This can compromise the confidentiality and integrity of AI models and data processed by Cocos AI. Since the exact deployment numbers are unknown, it's difficult to assess the full scope, but this vulnerability represents a significant risk for any organization using Cocos AI within their infrastructure.

## Recommendation

*   Apply available hardening measures such as keeping TEE firmware and microcode up to date to reduce the key-extraction surface as mentioned in the overview.
*   Define strict attestation policies that validate all available report fields, including firmware versions, TCB levels, and platform configuration registers as noted in the overview.
*   Enable mutual aTLS with CA-signed certificates where deployment architecture permits to mitigate the vulnerability as suggested in the overview.
*   Monitor for unusual network activity originating from Cocos AI servers that may indicate TLS session relaying, using a network monitoring tool.
