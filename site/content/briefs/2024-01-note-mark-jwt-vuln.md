---
title: Note Mark JWT Secret Weakness Allows Account Takeover
slug: 2024-01-note-mark-jwt-vuln
description: Note Mark is vulnerable to a JWT secret weakness that allows for full account takeover via token forgery by accepting secrets as short as 1 byte, enabling attackers to crack the signing secret offline and forge valid JWTs for any user.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - jwt
  - account-takeover
  - vulnerability
products:
  - note-mark/backend
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://github.com/advisories/GHSA-q6mh-rqwh-g786
rules:
  - title: Detect Weak JWT Secret Usage
    description: Detects Note Mark instances using JWT secrets shorter than 32 bytes after base64 decoding, indicating a potential vulnerability to CVE-2026-44523.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - process_creation
      - linux
  - title: Detect JWT Forgery Attempts via Unexpected User-Agent
    description: Detects potential JWT forgery attempts by monitoring user agents associated with forged tokens. This rule may help identify unexpected user agent strings.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

Note Mark is vulnerable to a critical security flaw related to the handling of JWT secrets. Specifically, the application does not enforce a minimum length or entropy on the `JWT_SECRET` configuration value. This means that the application accepts any base64-decodable secret, regardless of its size, even secrets as short as a single byte. According to RFC 7518 Section 3.2, HS256 keys must be at least 256 bits (32 bytes), but this is not enforced in Note Mark. This vulnerability, identified as CVE-2026-44523, allows attackers to compromise user accounts completely.

## Attack Chain

1. Deploy a vulnerable instance of Note Mark with a weak `JWT_SECRET` (less than 32 bytes after base64 decoding).
2. An attacker registers a new user account on the vulnerable Note Mark instance.
3. The attacker captures a valid `Auth-Session-Token` cookie from the registration or login process.
4. The attacker uses offline brute-force or dictionary attacks to crack the weak signing secret, such as using a Python script to decode the token with different secret values.
5. Once the secret is recovered, the attacker forges a new JWT for an arbitrary user UUID, potentially including an administrator account, and extends the expiry time.
6. The attacker sends the forged token in a request to the server.
7. The server incorrectly validates the forged token due to the compromised secret.
8. The server returns a 200 OK response, authenticating the attacker as the targeted user, granting unauthorized access to sensitive data and functionality.

## Impact

Successful exploitation of this vulnerability allows an attacker to perform full account takeover across the entire Note Mark application. The attacker can forge valid JWTs for any user, including administrators, without needing to know any actual user credentials. There is no server-side detection or rate-limiting possible, allowing the attacker to gain complete control over user accounts and data, potentially leading to data breaches, unauthorized modifications, and complete system compromise.

## Recommendation

*   Enforce a minimum length of 32 bytes (256 bits) for JWT secrets after base64 decoding to prevent brute-force attacks. This directly addresses the core vulnerability (CVE-2026-44523).
*   Reject weak secrets during configuration parsing within the `Base64Decoded.UnmarshalText` function or during config validation to prevent deployment with insecure secrets.
*   Deploy the Sigma rule `Detect Weak JWT Secret Usage` to identify potentially vulnerable Note Mark instances that do not meet the minimum key size requirements.
