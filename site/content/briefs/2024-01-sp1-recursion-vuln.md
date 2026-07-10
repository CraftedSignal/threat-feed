---
title: SP1 V6 Recursion Circuit Row-Count Binding Gap Vulnerability
slug: 2024-01-sp1-recursion-vuln
description: A soundness vulnerability in the SP1 V6 recursive shard verifier allows a malicious prover to construct a recursive proof from a shard proof that the native verifier would reject due to inconsistent trace shapes, potentially leading to data forgery and circuit misrepresentation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - soundness-vulnerability
  - recursive-proof
  - data-forgery
products:
  - SP1
  - sp1_sdk
  - sp1_recursion_circuit
  - sp1_prover
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-63x8-x938-vx33
rules:
  - title: Detect SP1 Recursive Proof Verification Failure
    description: Detects instances where the SP1 recursive proof verification fails, indicating a potential exploit of the row-count binding gap vulnerability.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - application
      - linux
  - title: Detect SP1 Shard Proof Verification Failure
    description: Detects instances where the SP1 shard proof verification fails, indicating a potential exploit of the row-count binding gap vulnerability.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - application
      - linux
rules_count: 2
---

A critical soundness vulnerability affects the SP1 V6 recursive shard verifier (versions 6.0.0 through 6.0.2). This flaw allows a malicious prover to generate a recursive proof from a shard proof that would be rejected by the native verifier. The core issue resides within the jagged PCS verifier integrated into the recursion circuit. The vulnerability stems from a missing consistency check, which permits the use of distinct trace shapes for commitment binding and polynomial evaluation.  Exploitation could lead to data forgery and, more seriously, misrepresentation of the circuit structure itself, by manipulating preprocessed traces that encode circuit selectors and permutation layouts. While a full exploit demonstrating arbitrary statement proving is not yet available, the underlying soundness violation necessitates immediate attention and mitigation. This vulnerability was reported on April 14, 2026.

## Attack Chain

1.  Attacker exploits the vulnerability in SP1 V6 recursive shard verifier (versions 6.0.0-6.0.2).
2.  The attacker crafts a malicious shard proof.
3.  The malicious proof leverages different trace shapes for commitment binding and polynomial evaluation within the jagged PCS verifier.
4.  Due to the missing consistency check in the recursion sub-circuit, the malicious proof bypasses the verifier.
5.  The attacker constructs a recursive proof based on the manipulated shard proof.
6.  The attacker leverages the forged data or misrepresented circuit structure to their advantage.
7. The attacker gains unauthorized access.
8.  Successful exploitation leads to data forgery or misrepresentation of circuit logic.

## Impact

This vulnerability enables a malicious prover to forge data within the SP1 system or to misrepresent the circuit structure itself. Although a full exploit demonstrating arbitrary statement proving has not been created, successful exploitation could compromise the integrity of proofs generated using the SP1 V6 recursive shard verifier, potentially affecting any system relying on the validity of these proofs.  The vulnerability impacts applications using SP1 for cryptographic proofs and secure computation.

## Recommendation

*   Upgrade to a patched version of the `sp1_sdk`, `sp1_recursion_circuit`, and `sp1_prover` packages that addresses the vulnerability (versions > 6.0.2).
*   Implement runtime validation of trace shapes used in commitment binding and polynomial evaluation to detect potential inconsistencies, focusing on the area described in the overview.
*   Monitor for unexpected behavior from SP1 verifiers, specifically those related to recursive proofs and shard verification, using newly developed Sigma rules for alerting.
*   Deploy the Sigma rules provided in this brief to your SIEM and tune for your environment.
