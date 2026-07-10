---
title: AVideo CORS Origin Reflection with Credentials Leads to Account Takeover
slug: 2024-01-26-avideo-cors
description: The AVideo platform is vulnerable to CORS origin reflection, allowing attackers to steal user PII, livestream keys, and perform unauthorized actions by exploiting the permissive `allowOrigin` function on sensitive API endpoints.
date: "2024-01-26T18:21:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - avideo
  - cors
  - account-takeover
  - web-application
vendors:
  - AVideo
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555.003
    technique_name: Credentials from Password Stores on Web Servers
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-ccq9-r5cw-5hwq
iocs:
  - type: url
    value: https://TARGET/plugin/API/get.json.php?APIName=user
  - type: url
    value: https://attacker.example/collect
  - type: domain
    value: attacker.example
ioc_counts:
  domain: 1
  url: 2
rules:
  - title: Detect AVideo API Access From Unknown Origins
    description: Detects requests to the AVideo API endpoints from origins that are not the expected domain. This can indicate a CORS exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Exfiltration to Attacker Controlled Domain
    description: Detects beaconing activity towards a known attacker controlled domain.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - exfiltration
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

AVideo, a video-sharing platform, contains a critical vulnerability in its CORS implementation. The `allowOrigin($allowAll=true)` function in `objects/functions.php` unconditionally reflects the `Origin` header, along with `Access-Control-Allow-Credentials: true`, on the `plugin/API/get.json.php` and `plugin/API/set.json.php` endpoints. These API endpoints handle sensitive user data retrieval, authentication, and state-changing operations. Combined with the application's `SameSite=None` session cookie policy, this allows attackers to bypass CORS restrictions, enabling credentialed cross-origin requests. By hosting a malicious webpage, an attacker can steal user PII (email, name, address, phone number, birth date), livestream credentials, and perform unauthorized actions on behalf of a logged-in user. This vulnerability affects AVideo versions 29.0 and earlier. The issue was introduced due to an oversight in a previous fix (commit `986e64aad`) which addressed CORS handling for null origins but neglected the more dangerous `$allowAll=true` path.

## Attack Chain

1. The attacker crafts a malicious HTML page hosted on a domain they control (e.g., `attacker.example`). This page contains JavaScript code designed to make a cross-origin request to the vulnerable AVideo instance.
2. A logged-in AVideo user visits the attacker's malicious page.
3. The JavaScript on the attacker's page sends a credentialed GET request to the `https://TARGET/plugin/API/get.json.php?APIName=user` endpoint with `credentials: 'include'`.
4. The AVideo server's `allowOrigin` function reflects the attacker's origin in the `Access-Control-Allow-Origin` header, along with setting `Access-Control-Allow-Credentials: true`.
5. The attacker's JavaScript receives the API response containing the victim's sensitive data, including email, name, address, phone number, admin status, livestream server URL with embedded password, and encrypted stream key.
6. The attacker exfiltrates the stolen data to their server (e.g., `https://attacker.example/collect`) using `navigator.sendBeacon`.
7. (Optional) The attacker crafts further requests to `set.json.php` to perform actions on the victim's behalf, such as modifying video settings or other account-related configurations.

## Impact

Successful exploitation allows an attacker to steal sensitive user data, including email, full name, address, phone number, and birth date, from any logged-in user who visits the attacker-controlled page. The attacker can also compromise user accounts by stealing livestream credentials, allowing them to hijack live streams. Exposure of admin status and permissions facilitates targeted attacks on privileged accounts. Furthermore, the attacker can perform state modifications on behalf of the victim through the `set.json.php` endpoint, potentially disrupting service or causing further damage. Due to the nature of the vulnerability, a single attacker page can harvest data from every logged-in visitor, leading to mass exploitation.

## Recommendation

*   Deploy the Sigma rule `Detect AVideo API Access From Unknown Origins` to identify requests to the vulnerable API endpoints originating from domains not explicitly allowed.
*   Apply the recommended fix provided in the advisory by replacing the permissive origin reflection in the `allowOrigin()` function with proper validation against the site's configured domain.
*   Audit webserver logs for requests to `/plugin/API/get.json.php` and `/plugin/API/set.json.php` where the Origin header does not match the expected domain to identify potential exploitation attempts (reference IOC: vulnerable API endpoint).
*   Consider separating truly public endpoints from sensitive API endpoints with different CORS policies.
*   Monitor network traffic for connections to attacker-controlled domains like `attacker.example` (reference IOC: attacker controlled domain).
