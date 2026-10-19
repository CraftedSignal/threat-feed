---
title: Integrity-Verification Downgrade Vulnerability in Apache Camel PGP
slug: 2026-10-camel-pgp-integrity
description: An integrity-verification downgrade in camel-crypto-pgp allows attackers to bypass modification detection by using legacy OpenPGP packets, potentially leading to the acceptance and decryption of malleable ciphertext.
date: "2026-10-19T12:17:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - apache-camel
  - cryptography
vendors:
  - Apache
products:
  - camel-crypto-pgp (4.0.0 to < 4.18.5, 4.19.0 to < 4.22.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The sender or anyone able to rewrite the message in transit decided whether the integrity check applied at all.
    confidence_band: high
cves:
  - id: CVE-2026-85243
    cvss: 5.9
references:
  - https://camel.apache.org/security/CVE-2026-85243.html
  - https://issues.apache.org/jira/browse/CAMEL-24441
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Apache Camel to 4.18.5, 4.22.1, or 4.23.0
      owner: IT Operations
      due: 72h
      evidence: Fixed versions identified in CVE-2026-85243 advisory
  mitigation_plan:
    - priority: immediate
      action: Implement packet header inspection for pre-unmarshal filtering of legacy PGP packets
      owner: IT Operations
      addresses: CVE-2026-85243
      evidence: Mitigation if you cannot upgrade documentation
---

Apache Camel’s `camel-crypto-pgp` component is vulnerable to an integrity-verification downgrade (CVE-2026-85243). The `unmarshal()` process only enforces modification detection checks when messages use OpenPGP symmetrically encrypted integrity-protected data packets. Messages utilizing older symmetrically encrypted data packets skip this integrity check entirely. Because the packet type is determined by the message producer, an attacker or a man-in-the-middle can choose to send legacy packets to bypass integrity validation. This allows the decryption of malleable ciphertext that would otherwise be rejected, potentially leading to unauthorized data processing. This issue affects versions from 4.0.0 before 4.18.5, and 4.19.0 before 4.22.1. The fix introduces a `requireIntegrityProtection` option, which defaults to `true` and enforces the use of protected packets.

## Impact

Successful exploitation allows for the decryption of unauthenticated and potentially modified PGP-encrypted messages. This impact is significant in environments relying on Camel for secure data ingestion, as it circumvents the fundamental guarantee that decrypted content has not been tampered with in transit. Organizations across sectors utilizing Apache Camel for PGP data processing are at risk if they communicate with untrusted or compromised external entities that can influence message packet selection.

## Recommendation

* Upgrade Apache Camel to versions 4.18.5, 4.22.1, or 4.23.0 to leverage the new `requireIntegrityProtection` security option.
* If immediate patching is not possible, implement a pre-processing check to inspect incoming OpenPGP packet headers and reject any message that does not utilize the integrity-protected data packet format before it reaches the `unmarshal()` function.
* Review existing Camel routes using `camel-crypto-pgp` to ensure that `requireIntegrityProtection` is set to `true` and evaluate if incoming traffic can be limited to trusted sources that strictly use modern PGP packet types.
