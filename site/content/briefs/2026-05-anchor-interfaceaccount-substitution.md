---
title: 'Anchor: InterfaceAccount Allows Account Substitution'
slug: 2026-05-anchor-interfaceaccount-substitution
description: The `InterfaceAccount` in `anchor-lang` allows an unexpected account type to be passed due to disabled discriminator checking, patched in version 1.0.0-rc.2 and later.
date: "2026-05-13T15:36:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - anchor
  - solana
  - interfaceaccount
  - account-substitution
vendors:
  - Solana Foundation
products:
  - anchor-lang
references:
  - https://github.com/advisories/GHSA-429q-fhh4-r6hj
  - https://github.com/solana-foundation/anchor/pull/3837
  - https://github.com/solana-foundation/anchor/pull/4139
rules:
  - title: Detect Solana Program Using Vulnerable Anchor Version
    description: Detects Solana programs using anchor-lang version 1.0.0-rc.1, which contains a vulnerable InterfaceAccount implementation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1608
    data_sources:
      - process_creation
      - linux
  - title: Detect Solana Program Deployments with Specific Anchor Version
    description: Detects Solana program deployments with anchor-lang version 1.0.0-rc.1 which contains a vulnerable InterfaceAccount implementation.  This relies on capturing deployment commands.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1608
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A vulnerability exists within the `InterfaceAccount` type in the `anchor-lang` package of the Anchor framework. This flaw allows for the substitution of account types because discriminator checking was unintentionally disabled in pull request #3837. An attacker could potentially exploit this by passing an account of an unexpected type, leading to unexpected behavior in Solana programs. The vulnerability affects version 1.0.0-rc.1. The fix was implemented in pull request #4139 and released in `1.0.0-rc.2`. Users are strongly advised to upgrade to the latest released version of Anchor 1.0 to mitigate this risk. This impacts programs utilizing the Anchor framework on the Solana blockchain.

## Attack Chain

1. An attacker identifies a Solana program utilizing `InterfaceAccount` with Anchor version 1.0.0-rc.1.
2. The attacker crafts a malicious transaction that attempts to pass an account of an incorrect type to the program via `InterfaceAccount`.
3. The program, lacking discriminator checking due to the vulnerability, accepts the incorrect account.
4. The program attempts to process the provided account based on the expected type.
5. Due to type mismatch, the program may experience unexpected behavior, such as data corruption.
6. The attacker leverages the corrupted data to manipulate program logic.
7. The attacker is able to perform unauthorized actions within the Solana program.
8. This can lead to financial loss, unauthorized data access, or denial of service for other users.

## Impact

The vulnerability allows attackers to substitute account types in Solana programs using the Anchor framework's `InterfaceAccount`, potentially leading to data corruption and unauthorized actions.  This impacts any Solana program using the vulnerable `InterfaceAccount` in `anchor-lang` version 1.0.0-rc.1. Successful exploitation could result in financial loss, data breaches, or denial-of-service for users of the affected Solana programs.

## Recommendation

*   Upgrade to the latest released version of Anchor 1.0 (>= 1.0.0-rc.2) as described in the advisory to patch the vulnerable `InterfaceAccount` type.
*   Examine your Solana programs for uses of `InterfaceAccount` in conjunction with `anchor-lang` 1.0.0-rc.1 and prioritize patching these programs.
*   Monitor Solana program activity for unexpected account interactions and type mismatches as a potential indicator of exploitation.
