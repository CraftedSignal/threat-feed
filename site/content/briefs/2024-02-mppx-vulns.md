---
title: MPPX Payment Bypass and Griefing Vulnerabilities
slug: 2024-02-mppx-vulns
description: Multiple vulnerabilities in the `mppx` npm package (versions prior to 0.4.8) allow for payment bypass, transaction replay attacks, fee manipulation, signature bypass, and channel griefing, potentially leading to financial loss and service disruption.
date: "2024-02-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - npm
  - vulnerability
  - payment bypass
products:
  - mppx
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
  - tactic_id: TA0009
    tactic_name: Impact
    technique_id: T1498
    technique_name: Internal Defacement
references:
  - https://github.com/advisories/GHSA-8x4m-qw58-3pcx
rules:
  - title: Detect Free Tempo/Charge Requests (Pull Mode)
    description: Detects potential exploitation of the 'tempo/charge' endpoint in pull mode, characterized by a lack of transfer log verification.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious HTTP Status Codes on tempo/session endpoint
    description: Detects unusual HTTP status codes on the tempo/session endpoint, potentially indicating vulnerability exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `mppx` npm package, a payment processing library, contains several critical vulnerabilities that could be exploited to bypass payment requirements, manipulate transaction fees, and disrupt payment channels. These vulnerabilities affect versions prior to 0.4.8, and arise from insufficient validation of transaction hashes, missing transfer log verification, cross-route scope confusion, and weaknesses in channel ID binding. Successful exploitation could allow attackers to perform free transactions, force others to pay their fees, or render payment channels unusable, leading to significant financial losses and reputational damage for applications relying on the vulnerable library.

## Attack Chain

1. **Initial Access:** An attacker identifies a vulnerable application using a version of the `mppx` npm package prior to 0.4.8.
2. **Transaction Replay:** The attacker replays `tempo/charge` transaction hashes across push/pull modes or charge/session endpoints to duplicate payments or bypass charges.
3. **Free Requests (Pull Mode):** The attacker performs free `tempo/charge` requests by exploiting missing transfer log verification in pull mode.
4. **Fee Manipulation:** The attacker manipulates the fee payer of a `tempo/charge` handler into paying for their requests by exploiting the missing sender signature check.
5. **Voucher Bypass:** The attacker bypasses `tempo/session` voucher signature verification to gain unauthorized access.
6. **Channel Hijacking:** The attacker piggybacks off existing `tempo/session` channels by reusing settle vouchers and exploiting weak channel ID binding.
7. **Griefing:** The attacker griefs `tempo/session` channels via force-close detection bypass by exploiting the fact that `closeRequestedAt` is not persisted.
8. **Impact:** The attacker successfully bypasses payment, manipulates fees, or disrupts payment channels, resulting in financial loss and service disruption for the targeted application.

## Impact

Successful exploitation of these vulnerabilities could lead to significant financial losses for applications using the vulnerable versions of the `mppx` package. Attackers can perform free transactions at the expense of legitimate users or the service provider. Moreover, attackers can grief payment channels, rendering them unusable and disrupting services that rely on them. The number of affected applications is unknown, but any application utilizing `mppx` prior to version 0.4.8 is potentially vulnerable.

## Recommendation

*   Upgrade the `mppx` npm package to version 0.4.8 or later to patch the vulnerabilities (reference: Patches section).
*   Implement robust input validation and integrity checks for all transaction-related data, especially when using `tempo/charge` and `tempo/session` (reference: Overview).
*   Monitor network traffic for unusual patterns indicative of transaction replay attacks or attempts to bypass payment mechanisms.
*   Deploy the Sigma rule to detect potential exploitation attempts related to free requests.
