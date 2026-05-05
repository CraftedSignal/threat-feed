---
title: AVideo API Secret Disclosure Leads to Unauthorized Access
slug: 2024-01-avideo-api-disclosure
description: AVideo version 29.0 and earlier is vulnerable to unauthenticated API secret disclosure via a publicly accessible endpoint, allowing unauthorized access to protected API endpoints.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - avideo
  - api-disclosure
  - unauthorized-access
vendors:
  - wwbn
products:
  - AVideo (<= 29.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-xr49-f4rh-qcjf
rules:
  - title: AVideo API Secret Disclosure Attempt
    description: Detects attempts to access the AVideo plugins.json.php endpoint which may expose the APISecret.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
  - title: AVideo Unauthorized API Access via APISecret
    description: Detects unauthorized API access attempts using a potentially disclosed APISecret.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AVideo, a video-sharing platform, is vulnerable to a critical security flaw that allows unauthenticated users to access sensitive API secrets. Specifically, the `objects/plugins.json.php` endpoint, intended to provide plugin configuration details, inadvertently exposes the `APISecret` within the `object_data`. This vulnerability, present in versions 29.0 and earlier, allows an attacker to bypass authentication and directly interact with protected API endpoints. By extracting the `APISecret`, an attacker can then craft API requests to access restricted data, such as user lists, without proper authorization. This poses a significant risk to data confidentiality and integrity within AVideo installations.

## Attack Chain

1. An unauthenticated attacker discovers the publicly accessible `objects/plugins.json.php` endpoint.
2. The attacker sends an HTTP GET request to `objects/plugins.json.php` to retrieve plugin configurations.
3. The server responds with a JSON payload containing plugin `object_data`, including the `APISecret`.
4. The attacker extracts the `APISecret` from the JSON response.
5. The attacker crafts a malicious API request to the `plugin/API/get.json.php` endpoint, including the `APISecret` as an authentication token.
6. The attacker specifies the desired `APIName` (e.g., `users_list`) and other parameters (e.g., `rowCount`, `current`) in the API request.
7. The server incorrectly validates the request based on the provided `APISecret`.
8. The server responds with the requested data, granting the attacker unauthorized access to protected information.

## Impact

Successful exploitation of this vulnerability grants unauthorized access to sensitive data managed by the AVideo platform. An attacker could potentially access user lists and other restricted information. The number of affected installations is currently unknown, but any instance running AVideo version 29.0 or earlier is susceptible. This can lead to data breaches, privacy violations, and potential misuse of user information.

## Recommendation

*   Apply the recommended fix of requiring admin authentication for the full plugin inventory/config endpoint (as suggested in the advisory).
*   Deploy the Sigma rule "AVideo API Secret Disclosure Attempt" to detect attempts to access the vulnerable `objects/plugins.json.php` endpoint.
*   Deploy the Sigma rule "AVideo Unauthorized API Access via APISecret" to detect unauthorized API calls using a disclosed API secret.
