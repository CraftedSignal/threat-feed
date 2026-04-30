---
title: CVE-2018-0735 ECDSA Signature Generation Timing Attack
slug: 2024-01-ecdsa-timing-attack
description: CVE-2018-0735 is a timing attack vulnerability in ECDSA signature generation affecting Microsoft products, potentially allowing attackers to recover private keys.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ecdsa
  - timing-attack
  - cryptography
vendors:
  - Microsoft
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
cves:
  - id: CVE-2018-0735
    cvss: 5.9
    epss: 0.04803
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2018-0735
rules:
  - title: Detect Potential ECDSA Timing Attack - High Volume Signature Requests
    description: This rule detects a high volume of requests to the same endpoint that performs ECDSA signature generation, which may indicate an attempt to collect timing data for a timing attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
      - linux
  - title: Detect ECDSA timing attack by observing delays
    description: This rule detects possible ECDSA timing attack if a certain uri takes long time to respond
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2018-0735 describes a timing attack vulnerability affecting the Elliptic Curve Digital Signature Algorithm (ECDSA) implementation within certain Microsoft products. Successful exploitation of this vulnerability could allow a remote attacker to recover the private key used to generate digital signatures. The vulnerability stems from the time it takes to generate signatures, which varies in ways predictable to an attacker. ECDSA is commonly used for authentication and encryption, making this a serious concern. While the specific affected products are not detailed without enabling JavaScript on the source webpage, the vulnerability has the potential to impact various applications and services that rely on Microsoft's ECDSA implementation for cryptographic operations.

## Attack Chain

Due to limited information from the source, a detailed attack chain is not available. However, a general ECDSA timing attack would involve the following steps:

1. The attacker identifies a target system or application utilizing a vulnerable ECDSA implementation from Microsoft.
2. The attacker initiates a series of signature requests, potentially through legitimate or malicious channels depending on the application.
3. The attacker measures the time taken to generate each signature with high precision.
4. The attacker performs statistical analysis on the timing data, looking for correlations between the timing and the secret nonce value used during signature generation.
5. Through repeated signature requests and timing analysis, the attacker reconstructs the secret nonce value used in multiple signature generations.
6. Once the attacker obtains sufficient nonce values and corresponding signatures, they can recover the private key used for signing.
7. With the private key, the attacker can forge signatures, impersonate the legitimate entity, and potentially gain unauthorized access to sensitive data or systems.

## Impact

Successful exploitation of CVE-2018-0735 could allow an attacker to recover the private key used for ECDSA signature generation. This could lead to a complete compromise of trust, as the attacker can forge signatures and impersonate the legitimate entity. The impact would vary depending on the specific application, but potential consequences include unauthorized access to systems, data breaches, and the ability to install malware or conduct man-in-the-middle attacks. The number of affected systems would depend on the widespread use of the vulnerable ECDSA implementation within Microsoft products.

## Recommendation

*   Consult Microsoft's Security Update Guide ([https://msrc.microsoft.com/update-guide/vulnerability/CVE-2018-0735](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2018-0735)) for specific affected products and available patches to mitigate CVE-2018-0735.
*   Although a specific network IOC is unavailable, monitor network traffic for unusual patterns or high volumes of signature requests originating from single sources to potentially detect reconnaissance activity related to timing attacks.
*   Enable detailed logging of cryptographic operations to enable investigation in case of suspicion of private key compromise.
