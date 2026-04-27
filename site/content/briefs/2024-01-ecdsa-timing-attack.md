---
title: CVE-2018-0735 ECDSA Signature Generation Timing Attack
slug: 2024-01-ecdsa-timing-attack
description: CVE-2018-0735 is a timing attack vulnerability in ECDSA signature generation affecting Microsoft products, potentially allowing attackers to recover private keys.
date: "2024-01-02T12:00:00Z"
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

CVE-2018-0735 describes a timing attack vulnerability affecting the Elliptic Curve Digital Signature Algorithm (ECDSA) implementation within certain Microsoft products. Successful exploitation of this vulnerability could allow a remote attacker to recover the private key used to generate digital signatures. The vulnerability stems from the time it takes to generate signatures, which varies in ways predictable to an attacker. ECDSA is commonly used for authentication and encryption, making this…
