---
title: Information Disclosure in SiYuan Kernel Enabling Offline Password Cracking
slug: 2026-09-siyuan-info-disclosure
description: An information disclosure vulnerability in SiYuan's API allows unauthorized remote readers to retrieve cryptographic material necessary for offline, unthrottled GPU-based cracking of encrypted notebook master passwords.
date: "2026-09-04T00:04:19Z"
lastmod: "2026-09-04T00:04:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:siyuan-note:siyuan:*:*:*:*:*:*:*:*
tags:
  - info-disclosure
  - cve
  - cryptanalysis
vendors:
  - SiYuan
products:
  - SiYuan Kernel (< 0.0.0-20260724102025-3bc014c7dc32)
  - SiYuan kernel (< 0.0.0-20260724091654-82e9ded423e4)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110.002
    technique_name: 'Brute Force: Password Cracking'
    evidence: An unauthenticated remote client can retrieve the Argon2id salt... reducing the security of every encrypted notebook to the master password's resistance to offline GPU cracking.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials in Files'
    evidence: The response's notebookCrypto object contains MasterSalt, KDFParams, KEKVerifier, VerifierNonce, and KEKMAC.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: An anonymous reader ... can therefore retrieve that document's per-block content and its reference/backlink topology.
    confidence_band: high
cves:
  - id: CVE-2026-72801
    cvss: 7.5
    epss: 0.00241
references:
  - https://github.com/advisories/GHSA-8x84-r2ff-h8pq
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72801
  - https://github.com/advisories/GHSA-vpjw-wf5h-cgpq
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72804
rules:
  - title: Detects CVE-2026-72801 Exploitation - Unauthorized API Access to Notebook Crypto
    description: Detects unauthorized access to the getConf or getNotebookConf API endpoints by identifying requests that reveal sensitive cryptographic metadata.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.002
    data_sources:
      - webserver
  - title: Detects CVE-2026-72804 Exploitation - Unauthorized Access to Graph Endpoints
    description: Detects potential exploitation of CVE-2026-72804 by monitoring for POST requests to graph endpoints that return successful status codes.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1005
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch SiYuan kernel to version 0.0.0-20260724102025-3bc014c7dc32
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies version 0.0.0-20260724102025-3bc014c7dc32 as the fixed version.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /api/system/getConf and /api/notebook/getNotebookConf at the reverse proxy or WAF layer.
      owner: Security Operations
      addresses: CVE-2026-72801
      evidence: Endpoints are reachable by publish readers; restricting access prevents unauthorized disclosure.
updates:
  - at: "2026-09-04T00:04:32Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-72804 Exploitation - Unauthorized Access to Graph Endpoints'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-vpjw-wf5h-cgpq
---

SiYuan kernel versions prior to 0.0.0-20260724102025-3bc014c7dc32 contain an information disclosure vulnerability (CVE-2026-72801) affecting the handling of encrypted notebook configuration metadata. Specifically, two API endpoints, `/api/system/getConf` and `/api/notebook/getNotebookConf`, fail to properly redact sensitive cryptographic material when accessed by non-administrator roles. 

An unauthenticated remote attacker or an unauthorized publish reader can retrieve the Argon2id salt, key derivation function (KDF) parameters, and master password verifiers (KEKVerifier/KEKMAC). Furthermore, the attacker can obtain the wrapped per-notebook data encryption key (WrappedDEK). Because these endpoints do not implement rate limiting or server-side auditing of guesses, an attacker can perform high-speed offline GPU cracking of the master password. Once the master password is recovered, the attacker uses the retrieved wrapped data key to decrypt notebook content. This vulnerability moves the threat of an offline filesystem attack to a remote, network-accessible pre-authentication exploitation vector.

## Attack Chain

1. Attacker identifies a SiYuan instance with publish mode enabled (default port 6808).
2. Attacker interacts with the `/api/system/getConf` endpoint using a low-privilege `RoleReader` token or as an anonymous reader if `Publish.Auth.Enable` is set to false.
3. The server erroneously returns the `NotebookCrypto` object, providing the attacker with the `MasterSalt`, `KDFParams`, `KEKVerifier`, and `KEKMAC`.
4. Attacker calls `/api/notebook/getNotebookConf` with a target `notebook_id` to retrieve the `BoxCrypt.WrappedDEK` and `WrapNonce`.
5. Attacker performs offline brute-force or dictionary attacks against the Argon2id KDF parameters using locally managed GPU clusters.
6. Successful password recovery derives the Key Encryption Key (KEK).
7. Attacker decrypts the `WrappedDEK` to obtain the notebook's master Data Encryption Key (DEK).
8. Attacker uses the DEK to decrypt the target notebook files, resulting in full data compromise.

## Impact

The vulnerability allows unauthorized remote parties to bypass the security of encrypted notebooks. Since the attack occurs entirely offline using retrieved parameters, it cannot be detected or blocked by server-side intrusion prevention systems. A successful attack results in the total loss of confidentiality for all notebooks stored within the compromised SiYuan instance.

## Recommendation

Prioritize patching the SiYuan kernel to version 0.0.0-20260724102025-3bc014c7dc32 or later. Ensure that the `HideConfSecret` function correctly excludes all `NotebookCrypto` fields for non-administrator roles, and verify that reader role filtering is enforced across all `BoxCrypt` related endpoints. Monitor web access logs for high-frequency POST requests to `/api/system/getConf` and `/api/notebook/getNotebookConf` originating from unauthorized or anonymous user agents.
