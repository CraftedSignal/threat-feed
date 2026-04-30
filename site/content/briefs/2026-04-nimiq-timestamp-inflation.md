---
title: Nimiq Blockchain Timestamp Manipulation Vulnerability
slug: 2026-04-nimiq-timestamp-inflation
description: A vulnerability in nimiq-blockchain versions 1.3.0 and earlier allows malicious validators to manipulate block timestamps, leading to inflation of the monetary supply.
date: "2026-04-09T21:16:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - blockchain
  - timestamp-manipulation
  - inflation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Credentials
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-40093
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40093
rules:
  - title: Detect Large Timestamp Discrepancies in Nimiq Blocks
    description: Detects blocks with timestamps significantly ahead of the current time, potentially indicating timestamp manipulation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - application
      - nimiq
  - title: Detect Unusual Reward Increases in Nimiq Blockchain
    description: Detects significant deviations from the expected block reward, potentially indicating monetary supply inflation.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - application
      - nimiq
rules_count: 2
---

Nimiq-blockchain, which provides persistent block storage for Nimiq's Rust implementation, is susceptible to a critical vulnerability. In versions 1.3.0 and earlier, the block timestamp validation lacks an upper bound check against the wall clock. This flaw enables a malicious block-producing validator to set block timestamps to an arbitrarily distant future. The vulnerability directly impacts reward calculations within the blockchain, specifically through `Policy::supply_at()` and `batch_delay()` in `blockchain/src/reward.rs`. By manipulating these timestamps, attackers can inflate the monetary supply beyond the intended emission schedule. This poses a significant threat to the integrity and economic stability of the Nimiq blockchain.

## Attack Chain

1.  Attacker gains control of a block-producing validator node within the Nimiq blockchain network.
2.  The attacker crafts a malicious block.
3.  The malicious block is created with a timestamp set arbitrarily far into the future.
4.  The vulnerable timestamp validation logic in Nimiq-blockchain (versions 1.3.0 and earlier) fails to detect the out-of-bounds timestamp due to the missing upper bound check.
5.  The malicious block is accepted and added to the blockchain.
6.  The inflated timestamp is used in reward calculations via `Policy::supply_at()` and `batch_delay()` functions in `blockchain/src/reward.rs`.
7.  The attacker receives an unfairly large block reward due to the manipulated timestamp.
8.  The total monetary supply of Nimiq is inflated beyond the intended emission schedule, devaluing existing holdings.

## Impact

The successful exploitation of CVE-2026-40093 can lead to a significant inflation of the Nimiq cryptocurrency supply. While the precise number of affected users or specific financial losses is currently unknown, any validator capable of producing blocks could potentially exploit this vulnerability. If successful, this attack undermines the economic model of Nimiq, potentially causing a loss of confidence in the cryptocurrency and a devaluation of existing holdings.

## Recommendation

*   Upgrade to a patched version of `nimiq-blockchain` that includes a proper upper bound check on block timestamps to address CVE-2026-40093.
*   Implement monitoring for sudden and unexpected increases in block rewards, focusing on inconsistencies with the expected emission schedule. This would require detailed knowledge of the blockchain's reward algorithm.
*   Review and harden the block validation logic within the Nimiq-blockchain implementation to prevent similar timestamp manipulation attacks in the future.
