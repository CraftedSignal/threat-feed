---
title: Nginx-UI Unauthenticated Initial Admin Claim Vulnerability
slug: 2024-01-nginx-ui-initial-admin-takeover
description: An unauthenticated network attacker can claim the initial administrator account on a fresh Nginx-UI instance during the first-run setup window by exploiting the publicly accessible /api/install endpoint.
date: "2024-01-03T17:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - nginx-ui
  - initial-access
  - authentication-bypass
vendors:
  - 0xJacky
products:
  - Nginx-UI (>= 2.0.0, <= 2.3.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-h27v-ph7w-m9fp
rules:
  - title: Detect Nginx-UI Unauthenticated Initial Admin Claim Attempt
    description: Detects attempts to claim the initial administrator account by sending a POST request to the /api/install endpoint without prior authentication.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Nginx-UI Public Key Request
    description: Detects requests to the /api/crypto/public_key endpoint, often preceding an initial admin claim attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `nginx-ui` application versions 2.0.0 through 2.3.5 are vulnerable to an unauthenticated initial administrator claim. An attacker can exploit this by sending a POST request to the `/api/install` endpoint during the first-run setup window. This allows the attacker to set the admin email, username, and password, effectively taking control of the application before the legitimate administrator. The vulnerability exists because the `/api/install` endpoint lacks proper authentication and the request-encryption flow only protects confidentiality, not authenticity. This can lead to complete compromise of the Nginx-UI instance and the systems it manages.

## Attack Chain

1. A fresh `nginx-ui` instance is deployed and exposed to the network.
2. An unauthenticated attacker sends a GET request to `/api/install` to verify the instance is unlocked (`"lock": false, "timeout": false`).
3. The attacker sends a POST request to `/api/crypto/public_key` to obtain the server's RSA public key.
4. The attacker encrypts a JSON payload containing the attacker's desired admin email, username, and password using the obtained public key. The payload is formatted as `{"email":"attacker@example.com","username":"attacker","password":"Password12345"}`.
5. The attacker base64-encodes the resulting ciphertext.
6. The attacker sends a POST request to `/api/install` with the base64-encoded ciphertext in the `encrypted_params` field (e.g., `{"encrypted_params":"base64_encoded_ciphertext"}`).
7. The server overwrites the initial admin user (ID 1) in the database with the attacker-provided credentials.
8. The attacker logs in to the `nginx-ui` interface with the attacker-controlled username and password, gaining complete control of the application.

## Impact

Successful exploitation allows an attacker to gain complete control over the `nginx-ui` application. Since `nginx-ui` manages Nginx configurations, certificates, and other host-level settings, this can lead to unauthorized configuration changes, certificate management abuse, backup manipulation, service disruption, and broader operational takeover of the managed environment. This vulnerability affects fresh, uninitialized instances that are reachable over the network during the installation window.

## Recommendation

*   Deploy the Sigma rule "Detect Nginx-UI Unauthenticated Initial Admin Claim Attempt" to your SIEM to identify exploitation attempts based on requests to the `/api/install` endpoint.
*   Apply network access controls to restrict access to the `nginx-ui` instance during the installation window.
*   Monitor web server logs for POST requests to `/api/install` and `/api/crypto/public_key` from unusual source IP addresses.
