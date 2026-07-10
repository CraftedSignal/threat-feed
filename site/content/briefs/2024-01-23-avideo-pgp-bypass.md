---
title: WWBN AVideo PGP 2FA Bypass via Weak Key Generation
slug: 2024-01-23-avideo-pgp-bypass
description: WWBN AVideo platform versions up to 26.0 generate weak 512-bit RSA keys for PGP 2FA, which can be easily factored to derive the private key and bypass the second authentication factor. Additionally, key generation endpoints lack authentication checks, exposing the system to resource exhaustion attacks.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - pgp
  - 2fa
  - bypass
  - cve-2026-33488
  - credential-access
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33488
rules:
  - title: Detect AVideo Key Generation Endpoint Access
    description: Detects access to the unauthenticated AVideo key generation endpoint, which could indicate attempted exploitation of CVE-2026-33488.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Encrypt Message Endpoint Access
    description: Detects access to the unauthenticated AVideo encrypt message endpoint, which could indicate attempted exploitation of CVE-2026-33488.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, contains a critical vulnerability (CVE-2026-33488) in versions up to and including 26.0. The vulnerability lies in the LoginControl plugin's PGP 2FA system, where the `createKeys()` function generates weak 512-bit RSA keys. These keys have been publicly factorable since 1999, making them susceptible to relatively quick compromise using commodity hardware. An attacker who retrieves a target user's public key can factor the 512-bit RSA modulus within hours, derive the complete private key, and decrypt any PGP 2FA challenge issued by the system, effectively bypassing the two-factor authentication. Furthermore, the `generateKeys.json.php` and `encryptMessage.json.php` endpoints lack authentication checks, allowing anonymous users to trigger CPU-intensive key generation, potentially leading to denial-of-service conditions. A patch is available in commit 00d979d87f8182095c8150609153a43f834e351e.

## Attack Chain

1. An attacker identifies a target user on an AVideo platform running a vulnerable version (<= 26.0).
2. The attacker accesses the target user's public key, likely exposed through the AVideo application or via direct request to the `generateKeys.json.php` endpoint, which lacks authentication.
3. The attacker utilizes readily available tools and commodity hardware to factor the 512-bit RSA modulus of the obtained public key.
4. The factoring process yields the target user's private key in a matter of hours.
5. The attacker intercepts a PGP 2FA challenge intended for the target user. This might be achieved through network sniffing or by compromising the user's email account.
6. The attacker uses the derived private key to decrypt the intercepted PGP 2FA challenge.
7. The attacker submits the decrypted challenge response to the AVideo platform.
8. The AVideo platform incorrectly validates the response, granting the attacker unauthorized access to the target user's account.

## Impact

Successful exploitation of CVE-2026-33488 allows attackers to completely bypass the PGP 2FA mechanism in WWBN AVideo platforms. This leads to unauthorized access to user accounts, potentially enabling attackers to steal sensitive video content, manipulate platform settings, or compromise user data. The lack of authentication on key generation endpoints can also lead to resource exhaustion and denial of service, disrupting the platform's availability. The impact is significant due to the complete circumvention of a critical security control.

## Recommendation

*   Apply the patch from commit 00d979d87f8182095c8150609153a43f834e351e to remediate CVE-2026-33488.
*   Implement authentication checks for the `generateKeys.json.php` and `encryptMessage.json.php` endpoints to prevent unauthorized key generation and potential denial-of-service attacks.
*   Deploy the Sigma rule "Detect AVideo Key Generation Endpoint Access" to monitor for unauthorized access to the vulnerable `generateKeys.json.php` and `encryptMessage.json.php` endpoints.
*   Review web server access logs for unusual activity related to the `/plugins/loginControl/` path.
