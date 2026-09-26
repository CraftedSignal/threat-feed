---
title: Information Disclosure in OpenZeppelin Confidential Contracts
slug: 2026-09-openzeppelin-confidential-contracts
description: The OpenZeppelin confidential-contracts library is vulnerable to private data leakage due to improper validation of encrypted handles returned by untrusted ERC-7984 tokens and recipients.
date: "2026-09-26T02:07:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - smart-contract
  - crypto
  - exfiltration
vendors:
  - OpenZeppelin
products:
  - confidential-contracts (< 0.3.2, >= 0.4.0-rc.0 < 0.4.2, >= 0.5.0-rc.0 < 0.5.2)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Effectively, this bug allows a malicious user to gain information about any private euint64 handle that the vesting wallet has access to via a malicious ERC-7984 token.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-29h2-jr22-frmh
action_plan:
  priority: elevated
  owners:
    - Security Engineering
    - Smart Contract Audit Team
  immediate_actions:
    - action: Upgrade @openzeppelin/confidential-contracts to version 0.3.2, 0.4.2, or 0.5.2
      owner: Security Engineering
      due: 24h
      evidence: 'Patches were fixed in the following patch releases: v0.5.2, v0.4.2, v0.3.2'
  mitigation_plan:
    - priority: immediate
      action: Review protocol usage of VestingWalletConfidential and IERC7984Receiver for vulnerable patterns
      owner: Smart Contract Audit Team
      addresses: confidential-contracts
      evidence: 'Both issues were fixed in the same patch releases: v0.5.2, v0.4.2, v0.3.2'
---

The OpenZeppelin confidential-contracts library contains critical logic errors in its handling of FHE (Fully Homomorphic Encryption) handles, specifically within the `VestingWalletConfidential` and `ERC7984` implementations. These flaws allow untrusted external parties to bypass access control list (ACL) verification when consuming handles returned during contract operations.

In the `VestingWalletConfidential` contract, a malicious ERC-7984 token can provide an alternative encrypted `euint64` handle during a `release` call. Because the contract fails to verify that the token has the necessary ACL authorization to access or return that specific handle, the contract inadvertently grants the caller access to the handle, leading to unauthorized data disclosure. A similar vulnerability exists in the `ERC7984` transfer callback, where a malicious recipient can return an arbitrary `ebool` handle during an `onConfidentialTransferReceived` call. By manipulating the refund logic, an attacker can extract the plaintext of the chosen `ebool` handle. These issues allow for unauthorized information retrieval from within the FHE environment, though they do not permit the theft of funds.

## Impact

The vulnerability affects users and protocols relying on the OpenZeppelin confidential-contracts library to manage private FHE-encrypted data. An attacker can gain unauthorized access to private `euint64` and `ebool` handles associated with the target wallet or token transactions. This results in the exposure of confidential data stored within the FHE encrypted state. While the impact is limited to information disclosure and does not allow for direct theft or draining of assets, it compromises the confidentiality guarantees of the smart contracts involved.

## Recommendation

- Upgrade the `confidential-contracts` library to versions 0.3.2, 0.4.2, or 0.5.2 immediately to apply the required ACL validation patches.
- Audit all custom implementations of `IERC7984Receiver` to ensure that callback logic does not blindly process encrypted handles returned by untrusted callers.
- Review smart contract interaction logs to identify any anomalous calls to `release` or `onConfidentialTransferReceived` involving unknown or non-standard token addresses that may have been used to probe for handle leakage.
