---
title: Node-Forge Certificate Chain Verification Bypass due to basicConstraints Violation
slug: 2026-07-node-forge-basic-constraints-bypass
description: Node-forge's certificate chain verification fails to enforce RFC 5280 basicConstraints, allowing leaf certificates without basicConstraints and keyUsage extensions to act as Certificate Authorities, leading to potential certificate forgery and man-in-the-middle attacks.
date: "2026-03-26T22:06:12Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - certificate-forgery
  - man-in-the-middle
  - node-forge
  - basicConstraints
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-2328-f5f3-gj25
iocs:
  - type: url
    value: https://doruk.ch
ioc_counts:
  url: 1
rules:
  - title: Detect Node-Forge Execution with Vulnerable Version
    description: Detects the execution of node-forge with a version vulnerable to the basicConstraints bypass vulnerability (CVE-2026-33896).
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Node-Forge Execution with Vulnerable Version (Linux)
    description: Detects the execution of node-forge with a version vulnerable to the basicConstraints bypass vulnerability (CVE-2026-33896) on Linux systems.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability exists in the node-forge npm package, specifically in versions 1.3.3 and earlier. The `pki.verifyCertificateChain()` function doesn't properly validate the `basicConstraints` extension during certificate chain verification, as specified in RFC 5280. When an intermediate certificate lacks both the `basicConstraints` and `keyUsage` extensions, the verification process incorrectly skips crucial checks, leading to the acceptance of the certificate as a valid CA. This allows attackers to forge certificates and perform man-in-the-middle attacks against applications using node-forge for custom PKI implementations, S/MIME signature verification, IoT device certificate validation, or any other non-native TLS certificate chain verification. The vulnerability was reported on 2026-03-10 via GitHub Security Advisory and assigned CVE-2026-33896.

## Attack Chain

1. The attacker obtains a valid leaf certificate (e.g., a TLS certificate) that lacks both the `basicConstraints` and `keyUsage` extensions.
2. The attacker uses this leaf certificate to sign a malicious certificate for a target domain (e.g., `victim.example.com`). The forged certificate appears to be issued by a legitimate but compromised CA.
3. The attacker intercepts network traffic between a client and a server.
4. The attacker presents the forged certificate chain (root CA -> compromised leaf CA -> malicious certificate for victim.example.com) to the client.
5. The client application uses node-forge's `pki.verifyCertificateChain()` function to validate the certificate chain.
6. Due to the missing `basicConstraints` and `keyUsage` extensions in the compromised leaf certificate, the validation process incorrectly accepts the certificate chain as valid.
7. The client establishes a TLS connection with the attacker, believing they are communicating with the legitimate server.
8. The attacker can then eavesdrop on, modify, or block the communication between the client and the server, leading to data theft, account compromise, or denial of service.

## Impact

Successful exploitation of this vulnerability can lead to complete compromise of applications relying on node-forge for certificate validation. An attacker can forge certificates for any domain, allowing them to perform man-in-the-middle attacks, intercept sensitive data, and impersonate legitimate services.  The number of potential victims is large, affecting any application using node-forge for custom PKI implementations, S/MIME signature verification, IoT device certificate validation, and any non-native-TLS certificate chain verification.  The severity is high, as it bypasses fundamental security controls related to certificate trust.

## Recommendation

*   Upgrade to node-forge version 1.3.4 or later, which includes the fix for CVE-2026-33896.
*   Deploy the following Sigma rule to detect the execution of node-forge with vulnerable versions to identify potentially affected systems.
*   If upgrading is not immediately feasible, consider patching the `lib/x509.js` file in your node-forge installation with the fix suggested in the advisory.
