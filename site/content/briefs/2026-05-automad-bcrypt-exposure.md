---
title: Automad Unauthenticated Exposure of Administrator Password Hashes and TOTP Secrets
slug: 2026-05-automad-bcrypt-exposure
description: Automad versions 2.0.0-alpha.1 through 2.0.0-beta.27 are vulnerable to CVE-2026-45332, a Broken Access Control vulnerability that allows an unauthenticated attacker to retrieve bcrypt password hashes of administrator accounts using a single POST request to the `/_api/user-collection/create-first-user` endpoint, potentially leading to credential compromise and information disclosure.
date: "2026-05-27T21:33:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - automad
  - broken-access-control
  - credential-access
  - cve-2026-45332
vendors:
  - Automad
products:
  - Automad (>= 2.0.0-alpha.1, <= 2.0.0-beta.27)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-xm76-r88j-vm3g
  - CVE-2026-45332
rules:
  - title: Detect Automad Unauthenticated Password Hash Exposure Attempt
    description: Detects CVE-2026-45332 exploitation — HTTP POST request to the `/_api/user-collection/create-first-user` endpoint, indicating a possible attempt to retrieve administrator password hashes.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect Automad Configuration Directory Path Disclosure
    description: Detects CVE-2026-45332 exploitation — HTTP POST response to `/_api/user-collection/create-first-user` exposing the server's filesystem path to the config directory.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
rules_count: 2
---

Automad, a file-based content management system, is vulnerable to a broken access control issue (CVE-2026-45332) affecting versions 2.0.0-alpha.1 through 2.0.0-beta.27. The vulnerability resides in the `/_api/user-collection/create-first-user` endpoint, which, after initial configuration, should be restricted. However, it remains publicly accessible and returns sensitive user data, including bcrypt password hashes for all administrator accounts. Version 2.0.0-beta.27 also exposes TOTP secrets. An unauthenticated attacker can exploit this vulnerability with a single POST request. This exposure allows for offline brute-force attacks on password hashes and potential bypass of two-factor authentication (in version 2.0.0-beta.27), posing a significant risk to Automad installations.

## Attack Chain

1. An unauthenticated attacker identifies an Automad instance running a vulnerable version (2.0.0-alpha.1 to 2.0.0-beta.27).
2. The attacker crafts an HTTP POST request to the `/_api/user-collection/create-first-user` endpoint.
3. The Automad server processes the request without authentication checks.
4. The server retrieves serialized user data, including bcrypt password hashes and, in version 2.0.0-beta.27, TOTP secrets.
5. The server returns the serialized user data in the JSON response body to the attacker.
6. The attacker extracts the bcrypt password hashes from the JSON response.
7. The attacker performs an offline brute-force or dictionary attack on the extracted password hashes to recover plaintext passwords.
8. If successful, the attacker uses the recovered plaintext passwords and, if applicable, the TOTP secret to gain unauthorized access to the Automad administration panel.

## Impact

Any publicly accessible Automad installation within the specified version range is vulnerable. Successful exploitation leads to the exposure of administrator account credentials, potentially granting attackers full control over the affected website. Version 2.0.0-beta.27 also exposes TOTP secrets, enabling bypass of two-factor authentication if a plaintext password is recovered. The response also exposes the absolute filesystem path to the configuration directory, which, while publicly documented, may expose environment-specific information.

## Recommendation

- Upgrade all Automad installations to version 2.0.0-beta.28 or later to remediate CVE-2026-45332 as recommended by the vendor.
- Deploy the Sigma rule "Detect Automad Unauthenticated Password Hash Exposure Attempt" to detect POST requests to the vulnerable endpoint `/_api/user-collection/create-first-user`.
- Monitor web server logs for unusual POST requests to the `/_api/user-collection/create-first-user` endpoint, focusing on requests originating from unexpected IP addresses.
