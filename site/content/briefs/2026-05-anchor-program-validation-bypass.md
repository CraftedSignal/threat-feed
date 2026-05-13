---
title: Anchor Program Validation Bypass Vulnerability
slug: 2026-05-anchor-program-validation-bypass
description: A logic error in anchor-lang versions 1.0.0 to 1.0.1 causes anchor programs to accept any program ID when requiring the system program ID, resulting in false assumptions that could lead to arbitrary CPI in programs invoking system program instructions, potentially leading to validation bypass and unauthorized account control.
date: "2026-05-13T15:37:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - anchor
  - solana
  - account-validation
  - cpi-bypass
vendors:
  - Solana Foundation
products:
  - anchor-lang
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-c6rc-8jpp-2fgc
  - CVE-2026-45137
rules:
  - title: Detect Anchor Program ID Validation Bypass
    description: Detects CVE-2026-45137 — Exploitation attempts where a program attempts to invoke another program by passing in an incorrect program ID, specifically looking for the ComputeBudget program being passed as the System program.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - program_execution
      - solana
rules_count: 1
---

Anchor is a framework for building Solana programs. A validation vulnerability exists in anchor-lang versions 1.0.0 and 1.0.1 where programs built with anchor incorrectly validate the `system_program` account. Specifically, the `TryFrom` implementation for `Program<'a, T>` compares the ID of T with `Pubkey::default()` to check whether anchor should allow any executable account or a specific account. Due to this logic, both `T = ()` and `T = System` exhibit the same behavior, allowing any executable account. This flaw allows attackers to pass arbitrary program IDs instead of the system program ID, causing false assumptions and enabling potential CPI and payment bypasses.

## Attack Chain

1. Attacker identifies a vulnerable Anchor program (version 1.0.0 or 1.0.1) that uses the `Program<'info, System>` type to ensure a valid system program account.
2. The attacker crafts a malicious transaction, replacing the expected system program ID with the ID of a program they control (e.g., the Compute Budget program, or a custom program).
3. The vulnerable program's `Initialize` function receives the attacker-provided program ID as the `system_program` account.
4. Due to the flawed validation logic, the Anchor runtime incorrectly accepts the attacker-provided program ID as a valid system program.
5. The vulnerable program constructs a transfer instruction using the (incorrect) attacker-supplied program ID.
6. The program invokes the transfer instruction, intending to transfer lamports using the system program. However, because the program ID is controlled by the attacker, no transfer occurs, or the transfer is redirected to an attacker-controlled program based on the malicious program logic.
7. The vulnerable program proceeds under the false assumption that the transfer has succeeded, potentially leading to incorrect state updates.
8. The attacker bypasses intended restrictions and potentially gains control of accounts meant to be owned by the system program, or blocks transfers.

## Impact

This vulnerability impacts on-chain programs that depend on the system program, potentially leading to CPI bypasses and unauthorized payment diversions. This could result in financial losses and compromised program functionality. The vulnerability affects programs using `rust/anchor-lang` in versions 1.0.0 and 1.0.1. The severity of the vulnerability is rated as high due to the potential for significant financial impact and unauthorized account control.

## Recommendation

- Upgrade `rust/anchor-lang` to version 1.0.2 or later to remediate the vulnerability.
- Deploy the provided Sigma rule `Detect Anchor Program ID Validation Bypass` to identify potential exploitation attempts targeting the vulnerable validation logic.
- Audit existing Anchor programs for improper system program account validation, specifically examining the `TryFrom<&'a AccountInfo<'a>>` implementation for `Program<'a, T>`.
- Use static analysis tools to detect vulnerable code patterns in Anchor programs that rely on system program interactions.
