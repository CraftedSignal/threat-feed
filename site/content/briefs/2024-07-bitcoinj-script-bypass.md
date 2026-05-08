---
title: bitcoinj ScriptExecution P2PKH/P2WPKH Verification Bypass
slug: 2024-07-bitcoinj-script-bypass
description: A vulnerability in bitcoinj's ScriptExecution.correctlySpends() allows attackers to bypass signature verification for P2PKH and P2WPKH spends, potentially leading to unauthorized transaction validation.
date: "2024-07-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - bitcoin
  - transaction-validation
  - script-execution
  - verification-bypass
vendors:
  - bitcoinj
products:
  - bitcoinj-core (>= 0.15, < 0.17.1)
references:
  - https://github.com/advisories/GHSA-hfcf-v2f8-x9pc
rules:
  - title: Detect BitcoinJ P2PKH Script Bypass
    description: Detects CVE-2026-44714 exploitation -- suspicious scriptSig size in P2PKH transactions indicating a potential signature bypass attempt in bitcoinj.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - process_creation
      - linux
  - title: Detect BitcoinJ P2WPKH Script Bypass
    description: Detects CVE-2026-44714 exploitation -- suspicious witness size in P2WPKH transactions indicating a potential signature bypass attempt in bitcoinj.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability exists within the bitcoinj library, specifically affecting versions 0.15 to 0.17.0. The `ScriptExecution.correctlySpends()` function contains flawed fast-path verification logic for standard Pay-to-Public-Key-Hash (P2PKH) and native Pay-to-Witness-Public-Key-Hash (P2WPKH) spends. This flaw allows an attacker to construct a transaction using an arbitrary keypair that bitcoinj will incorrectly validate as legitimate. This bypass occurs because bitcoinj fails to properly verify that the public key used in the signature matches the one committed to by the output being spent. Applications relying on bitcoinj for transaction validation are at risk of accepting fraudulent transactions. The vulnerability was reported on May 8th, 2026 and patched in versions 0.17.1 and later.

## Attack Chain

1.  Attacker identifies a vulnerable application using bitcoinj library (versions 0.15 to 0.17.0) for transaction validation.
2.  Attacker crafts a malicious transaction targeting a P2PKH or P2WPKH output of a victim.
3.  For P2PKH, the attacker creates a `scriptSig` containing an arbitrary signature and public key. The signature is created using attacker's private key over victim's output.
4.  For P2WPKH, the attacker creates a witness containing an arbitrary signature and public key. The signature is created using attacker's private key over victim's output.
5.  Attacker submits the malicious transaction to the vulnerable application.
6.  The application calls `ScriptExecution.correctlySpends()` for validation. Due to the flawed logic, the function verifies the attacker's signature against their public key but fails to validate the binding between the public key and the output being spent.
7.  The vulnerable application incorrectly validates the transaction as legitimate due to successful signature verification, even though the attacker does not own the output.
8.  The application processes the fraudulent transaction, leading to potential financial loss for the victim.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass signature verification in bitcoinj-based applications. This can result in the acceptance of fraudulent transactions, leading to financial losses for affected users or services. The scope of impact depends on the number of applications relying on vulnerable versions of bitcoinj for transaction validation. While the specific number of victims is unknown, the potential for widespread abuse exists given the library's usage within the Bitcoin ecosystem.

## Recommendation

*   Upgrade to bitcoinj version 0.17.1 or later to patch the vulnerability as mentioned in the [GHSA advisory](https://github.com/advisories/GHSA-hfcf-v2f8-x9pc).
*   Deploy the Sigma rule "Detect BitcoinJ P2PKH Script Bypass" to identify potential exploitation attempts in your environment.
*   Deploy the Sigma rule "Detect BitcoinJ P2WPKH Script Bypass" to identify potential exploitation attempts in your environment.
*   Review and audit any custom transaction validation logic that relies on `ScriptExecution.correctlySpends()` in affected applications.
