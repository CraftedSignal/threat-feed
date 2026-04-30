---
title: Fortra GoAnywhere MFT SSH Key Brute-Force Vulnerability (CVE-2025-14362)
slug: 2026-04-goanywhere-bruteforce
description: Fortra's GoAnywhere MFT prior to 7.10.0 is vulnerable to brute-force attacks on SSH keys because the login limit is not enforced on the SFTP service when Web Users are configured to log in with an SSH Key.
date: "2026-04-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - goanywhere
  - mft
  - bruteforce
  - ssh
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
cves:
  - id: CVE-2025-14362
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-14362
  - https://fortra.com/security/advisories/product-security/FI-2026-002
rules:
  - title: Detect Excessive Failed SSH Authentication Attempts on GoAnywhere MFT
    description: Detects a high number of failed SSH authentication attempts, potentially indicating a brute-force attack against GoAnywhere MFT.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - auth
      - linux
  - title: Detect Fortra GoAnywhere MFT service version via User-Agent
    description: Detects vulnerable Fortra GoAnywhere MFT service versions by checking the User-Agent string in HTTP requests. This is an informational rule that can help identify potentially vulnerable systems.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2025-14362 is a vulnerability affecting Fortra's GoAnywhere MFT servers prior to version 7.10.0. The vulnerability arises because the login limit is not enforced on the SFTP service when a Web User is configured to authenticate using an SSH key. This lack of enforcement allows attackers to conduct brute-force attacks against the SSH key, attempting to guess the key through repeated authentication attempts. Successful exploitation grants unauthorized access to the GoAnywhere MFT server, potentially leading to data breaches, system compromise, and other malicious activities. Defenders should prioritize patching vulnerable GoAnywhere MFT instances to version 7.10.0 or later.

## Attack Chain

1.  Attacker identifies a GoAnywhere MFT server running a version prior to 7.10.0.
2.  Attacker determines that the GoAnywhere MFT server allows Web Users to authenticate using SSH keys.
3.  Attacker attempts to authenticate to the SFTP service using a series of generated SSH keys.
4.  Due to the lack of login limit enforcement, the attacker can make unlimited authentication attempts without being locked out.
5.  The attacker continues brute-forcing SSH keys until a valid key is guessed, or an exploitable weakness is found.
6.  Upon successful authentication, the attacker gains unauthorized access to the GoAnywhere MFT server.
7.  The attacker can then upload/download arbitrary files, execute commands, and potentially move laterally within the network.
8.  The final objective is to exfiltrate sensitive data or establish a persistent foothold within the target environment.

## Impact

Successful exploitation of CVE-2025-14362 can lead to unauthorized access to sensitive data managed by the GoAnywhere MFT server. This could include financial records, customer data, intellectual property, and other confidential information. The number of victims is dependent on the exposure of vulnerable GoAnywhere MFT servers. Sectors commonly using MFT solutions, such as finance, healthcare, and government, are at increased risk. The impact of a successful attack can range from data breaches and financial loss to reputational damage and legal liabilities.

## Recommendation

*   Upgrade Fortra GoAnywhere MFT to version 7.10.0 or later to patch CVE-2025-14362 (reference: Overview).
*   Implement rate limiting on SSH authentication attempts at the network or host level to mitigate brute-force attacks, even after patching (reference: Attack Chain).
*   Monitor SFTP logs for excessive failed authentication attempts originating from the same source IP address using a Sigma rule similar to the one provided below (reference: Rules).
