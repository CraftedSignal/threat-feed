---
title: Information Disclosure in SiYuan Kernel Enabling Offline Password Cracking
slug: 2026-09-siyuan-info-disclosure
description: An information disclosure vulnerability in SiYuan's API allows unauthorized remote readers to retrieve cryptographic material necessary for offline, unthrottled GPU-based cracking of encrypted notebook master passwords.
date: "2026-09-04T00:04:19Z"
lastmod: "2026-09-05T00:07:52Z"
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
  - authentication-bypass
  - webserver
  - vulnerability
  - session-forgery
  - credential-disclosure
vendors:
  - SiYuan
products:
  - SiYuan Kernel (< 0.0.0-20260724102025-3bc014c7dc32)
  - SiYuan kernel (< 0.0.0-20260724091654-82e9ded423e4)
  - SiYuan Kernel (< 0.0.0-20260723031701-9c16e9851f0b)
  - SiYuan kernel (< 0.0.0-20260721013353-69db783b782a)
  - SiYuan kernel (< 0.0.0-20260725132049-2d8b98395a91)
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
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: By code inspection, a request forwarded through this proxy would reach the kernel with RemoteAddr = 127.0.0.1.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: CheckAuth grants RoleAdministrator to any request whose RemoteAddr is loopback (127.0.0.1), for a specific set of endpoints.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: An anonymous reader... can read the full rendered content of a document that has been explicitly marked publish-disabled.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The reader-facing path returns the session-cookie signing key.
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
  - https://github.com/advisories/GHSA-3mp7-4rh5-jrv9
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72809
  - https://github.com/advisories/GHSA-69mh-gvh4-8gp7
  - https://nvd.nist.gov/vuln/detail/CVE-2026-68587
  - https://github.com/advisories/GHSA-h4v5-crx2-3cv4
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72793
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
  - title: Detect CVE-2026-68587 Exploitation Attempt
    description: Detects unauthorized access attempts to SiYuan transaction endpoints that return sensitive rendered document content.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1592
    data_sources:
      - webserver
  - title: Detect SiYuan Configuration Disclosure Attempt
    description: Detects unauthorized access to the /api/system/getConf endpoint which may leak sensitive configuration secrets (CVE-2026-72793)
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 4
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
  - at: "2026-09-04T00:04:50Z"
    level: L2
    summary: added coverage for SiYuan Kernel (< 0.0.0-20260723031701-9c16e9851f0b)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-3mp7-4rh5-jrv9
  - at: "2026-09-04T00:05:15Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-68587 Exploitation Attempt'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-69mh-gvh4-8gp7
  - at: "2026-09-05T00:07:52Z"
    level: L2
    summary: 'added detection rule: Detect SiYuan Configuration Disclosure Attempt'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-h4v5-crx2-3cv4
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
