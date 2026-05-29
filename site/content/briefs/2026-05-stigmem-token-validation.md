---
title: Stigmem-node Federation Peer Token Timestamp Validation Vulnerability
slug: 2026-05-stigmem-token-validation
description: A timestamp handling issue in Stigmem-node's federation peer token validation could cause valid peer tokens to be incorrectly treated as expired, impacting availability and reliability of authenticated federation flows, affecting versions prior to 0.9.0a2.
date: "2026-05-29T22:15:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stigmem
  - token-validation
  - authentication
vendors:
  - Eidetic Labs
products:
  - stigmem-node
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/advisories/GHSA-xh5j-xjfq-qvvx
  - https://github.com/eidetic-labs/stigmem/releases/tag/v0.9.0a2
  - https://github.com/eidetic-labs/stigmem/blob/v0.9.0a2/CHANGELOG.md#L14-L35
  - https://github.com/eidetic-labs/stigmem/blob/v0.9.0a2/SECURITY.md
rules:
  - title: Detect Stigmem-node Authentication Failures Due to Token Expiry
    description: Detects stigmem-node authentication failures potentially caused by the timestamp validation issue, indicating possible exploitation or misconfiguration.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1550
    data_sources:
      - application
      - stigmem-node
rules_count: 1
---

A vulnerability exists in stigmem-node versions prior to 0.9.0a2 where federation peer token timestamp handling can cause valid peer tokens to be incorrectly evaluated as expired. This is due to a mismatch in how token timestamps are processed. An attacker could exploit this by leveraging federation peer authentication paths in vulnerable versions of stigmem-node, disrupting availability and reliability. This impacts deployments where Stigmem nodes use federation peer authentication. The vulnerability was patched in version 0.9.0a2.

## Attack Chain

1. An attacker attempts to authenticate with a Stigmem node using a valid federation peer token.
2. The Stigmem node, running a vulnerable version (prior to 0.9.0a2), receives the token.
3. The timestamp within the token is processed using an incorrect validation path.
4. Due to this incorrect handling, the token's timestamp is misinterpreted.
5. The Stigmem node determines the token to be expired, even if it is still valid.
6. Authentication fails, preventing the peer from accessing the Stigmem node's resources.
7. Legitimate federation flows are disrupted due to repeated authentication failures.
8. The attacker achieves a denial-of-service effect by preventing valid peers from authenticating.

## Impact

This vulnerability primarily impacts the availability and reliability of authenticated federation flows. Successful exploitation can prevent legitimate peers from authenticating with Stigmem nodes, disrupting normal operations. This could lead to service outages or impaired functionality for users relying on federated access. While the report doesn't specify the number of affected organizations, any deployment using stigmem-node versions prior to 0.9.0a2 and relying on federation peer authentication is potentially vulnerable.

## Recommendation

*   Upgrade stigmem-node to version 0.9.0a2 or later to remediate the vulnerability. Use `pip install --upgrade --pre stigmem-node` or `pip install --upgrade --pre 'stigmem[node]'` as detailed in the advisory.
*   Prior to upgrading, avoid mixing peer-token minting paths and restrict federation use to tightly controlled peers, as suggested in the workaround section.
*   Monitor stigmem-node logs for authentication failures involving federation peer tokens. While no specific rule is provided, look for errors related to token expiry.
*   Enable verbose logging to capture the details of the timestamp validation process. This may help diagnose issues and confirm the vulnerability.
