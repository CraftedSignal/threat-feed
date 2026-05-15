---
title: epa4all-client Improper Verification of Cryptographic Signature Vulnerability (CVE-2026-45575)
slug: 2026-05-epa4all-client-mitm
description: A man-in-the-middle attacker within the TI network can exploit CVE-2026-45575 in com.oviva.telematik:epa4all-client versions prior to 1.2.2 to substitute a forged discovery document and capture signed authentication material.
date: "2026-05-15T18:32:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - mitm
  - credential-access
vendors:
  - Oviva
products:
  - epa4all-client (< 1.2.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Man-in-the-Middle
references:
  - https://github.com/advisories/GHSA-gqx7-6552-67hf
  - MS-OVIVA-EPA4ALL-d453c1
iocs:
  - type: email
    value: contact@machinespirits.de
ioc_counts:
  email: 1
rules:
  - title: Detect CVE-2026-45575 Exploitation — Outbound Connection to Unexpected Domain
    description: Detects CVE-2026-45575 exploitation — Outbound network connection initiated by epa4all-client to a domain not on a known good list, potentially indicating a forged discovery document attack.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1557.001
    data_sources:
      - network_connection
      - windows
  - title: Detect CVE-2026-45575 Exploitation — Suspicious Process Connecting Outbound
    description: Detects CVE-2026-45575 exploitation — An outbound network connection initiated from the epa4all-client executable, indicative of potential malicious redirection.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1557.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The `epa4all-client` is vulnerable to a man-in-the-middle (MITM) attack (CVE-2026-45575) due to improper verification of cryptographic signatures. An attacker positioned within the TI network, capable of intercepting and modifying TLS traffic between the client and the Identity Provider (IDP), can substitute the legitimate discovery document with a forged one. This forged document redirects the `uri_puk_idp_enc` and `uri_puk_idp_sig` parameters to attacker-controlled URLs. This vulnerability affects versions of `com.oviva.telematik:epa4all-client` prior to 1.2.2. Successful exploitation allows the attacker to steal the SMC-B-signed challenge response, enabling unauthorized access.

## Attack Chain

1. The attacker performs a MITM attack on the TLS connection between the `epa4all-client` and the IDP within the TI network.
2. The attacker intercepts the legitimate discovery document transmitted from the IDP to the client.
3. The attacker substitutes the legitimate discovery document with a forged document crafted to redirect traffic to attacker-controlled endpoints.
4. The forged discovery document redirects `uri_puk_idp_enc` and `uri_puk_idp_sig` to attacker-controlled URLs.
5. The `epa4all-client`, trusting the forged document, encrypts the SMC-B-signed challenge response using the attacker's encryption key.
6. The client then POSTs the encrypted, signed authentication material to the attacker's designated authentication endpoint.
7. The attacker captures the signed authentication material from the POST request.
8. The attacker uses the captured authentication material to gain unauthorized access to protected resources or impersonate the user.

## Impact

Successful exploitation of CVE-2026-45575 allows an attacker to capture the SMC-B-signed challenge response, enabling unauthorized access to sensitive healthcare data or services within the Telematikinfrastruktur (TI) network. This could lead to data breaches, compliance violations, and potential misuse of patient information. The vulnerability impacts all deployments of `com.oviva.telematik:epa4all-client` versions prior to 1.2.2 within the TI network where a MITM attack is feasible.

## Recommendation

*   Upgrade `com.oviva.telematik:epa4all-client` to version 1.2.2 or later to incorporate the fix for CVE-2026-45575.
*   Implement network monitoring to detect suspicious TLS traffic patterns indicative of MITM attacks within the TI network.
*   Monitor network connections for connections to unusual or unexpected external URLs as a result of a forged discovery document.
*   Implement the network connection rule to monitor for connections to external IP addresses or domains, as this could indicate a forged discovery document has been used.
