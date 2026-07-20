---
title: CVE-2026-64620 - FreeRDP Heap-based Buffer Overflow
slug: 2026-07-freerdp-buffer-overflow
description: FreeRDP before version 3.28.0 contains a heap-based buffer overflow in the `crypto_rsa_common()` function, exploitable pre-authentication by an unauthenticated attacker crafting a malicious ciphertext to cause a denial of service on the server when a client uses RDP Standard Security.
date: "2026-07-20T12:23:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - buffer-overflow
  - denial-of-service
  - freerdp
  - cve
  - network
vendors:
  - FreeRDP Project
products:
  - FreeRDP (<=3.27.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can exploit this on the server side when a client selects RDP Standard Security.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: overflowing the 32-byte heap buffer by up to ~224 attacker-controlled bytes pre-authentication, resulting in denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-64620
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64620
---

A critical heap-based buffer overflow, identified as CVE-2026-64620, affects FreeRDP versions prior to 3.28.0 (specifically, 3.27.1 and earlier). This vulnerability resides in the `crypto_rsa_common()` function within `libfreerdp/crypto/crypto.c`, where a modular-exponentiation result is written to an output buffer before a bounds check is performed, leading to out-of-bounds writes. An unauthenticated attacker can exploit this on the server side when a client attempts to connect using RDP Standard Security. By leveraging the server's published RSA public key, the attacker can forge a ciphertext whose decrypted value exceeds a fixed 32-byte buffer. This can cause a heap overflow of up to approximately 224 attacker-controlled bytes pre-authentication, leading directly to a denial of service for the FreeRDP server. The flaw was publicly disclosed on July 20, 2026.

## Attack Chain

1. An unauthenticated attacker identifies a FreeRDP server vulnerable to CVE-2026-64620, meaning it is running FreeRDP version 3.27.1 or earlier.
2. The attacker initiates an RDP connection attempt to the target FreeRDP server.
3. During the connection handshake, the attacker forces the server to use RDP Standard Security.
4. The server responds by publishing its RSA public key, which the attacker intercepts.
5. Using the server's public key, the attacker crafts a malicious ciphertext designed to represent an encrypted client random value. This crafted ciphertext is specifically engineered such that its decrypted length will significantly exceed a 32-byte buffer used by the server.
6. The attacker sends this specially crafted ciphertext to the FreeRDP server as part of the client random exchange.
7. The server processes the client random using the vulnerable `crypto_rsa_common()` function, which decrypts the value.
8. During decryption, the `BN_bn2bin()` function writes the result into the allocated 32-byte buffer. However, due to the missing pre-check, the decrypted value overflows this buffer by up to approximately 224 bytes with attacker-controlled data.
9. This heap-based buffer overflow corrupts adjacent memory, causing the FreeRDP server process to crash, resulting in a denial of service.

## Impact

The successful exploitation of CVE-2026-64620 results in a denial of service (DoS) for the FreeRDP server. This can lead to significant operational disruption as legitimate users are unable to connect to their RDP sessions. Since the attack is pre-authentication and unauthenticated, it can be executed remotely with minimal effort, making affected servers susceptible to widespread availability issues. There are no specific victim counts or targeted sectors mentioned, but any organization using FreeRDP as a server component and exposed to the internet, or accessible by an internal attacker, is at risk of service interruption.

## Recommendation

* Patch CVE-2026-64620 immediately by upgrading all FreeRDP installations to version 3.28.0 or later.
* Enable comprehensive logging for FreeRDP server processes and monitor for unexpected crashes or restarts, which could indicate exploitation attempts or successful denial-of-service attacks.
