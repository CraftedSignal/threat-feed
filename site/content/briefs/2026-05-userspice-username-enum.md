---
title: userSpice Username Enumeration Vulnerability (CVE-2018-25350)
slug: 2026-05-userspice-username-enum
description: userSpice 4.3.24 contains a username enumeration vulnerability, allowing unauthenticated attackers to discover valid usernames by sending POST requests to the existingUsernameCheck.php endpoint and analyzing the response for the 'taken' string.
date: "2026-05-26T13:55:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - username-enumeration
  - cve-2018-25350
  - web-application
vendors:
  - userSpice
products:
  - userSpice
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2018-25350
    cvss: 9.8
    epss: 0.00076
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25350
  - https://www.exploit-db.com/exploits/44872
  - https://www.vulncheck.com/advisories/userspice-username-enumeration-via-existingusernamecheck-php
rules:
  - title: Detect userSpice Username Enumeration via existingUsernameCheck.php
    description: Detects CVE-2018-25350 exploitation — An unauthenticated attacker attempts to enumerate userSpice usernames by sending POST requests to the existingUsernameCheck.php endpoint.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
  - title: Detect userSpice Username Enumeration Response
    description: Detects CVE-2018-25350 exploitation — Detects a server response containing 'taken' after a POST request to the existingUsernameCheck.php endpoint, indicating a valid username.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
rules_count: 2
---

userSpice version 4.3.24 is vulnerable to a username enumeration attack. This vulnerability allows unauthenticated attackers to determine valid usernames within the application. By sending specially crafted POST requests to the `existingUsernameCheck.php` endpoint, attackers can analyze the response from the server to determine if a submitted username is valid. This is achieved by looking for the presence of the string 'taken' in the response text, indicating that the username exists. This vulnerability was reported in CVE-2018-25350. Exploitation of this vulnerability allows attackers to gather information for subsequent attacks, such as password brute-forcing or targeted phishing campaigns.

## Attack Chain

1. An unauthenticated attacker identifies the `existingUsernameCheck.php` endpoint.
2. The attacker crafts a POST request to `existingUsernameCheck.php` with a username to check.
3. The attacker sends the POST request to the server.
4. The server processes the request and checks if the provided username exists in the database.
5. The server responds with a text response.
6. The attacker analyzes the response text for the presence of the string "taken".
7. If "taken" is present, the attacker confirms the existence of the username.
8. The attacker repeats this process with different usernames to enumerate valid accounts.

## Impact

Successful exploitation of this vulnerability allows attackers to enumerate valid usernames on the userSpice 4.3.24 platform. While this vulnerability does not directly lead to account compromise, the enumerated usernames can be used in conjunction with other attack vectors, such as password brute-forcing or targeted phishing campaigns, to gain unauthorized access to user accounts. The number of potential victims depends on the number of userSpice installations and the number of accounts on those installations.

## Recommendation

*   Apply available patches or upgrades to userSpice to versions beyond 4.3.24 to remediate CVE-2018-25350.
*   Deploy the Sigma rule `Detect userSpice Username Enumeration via existingUsernameCheck.php` to your SIEM to identify potential enumeration attempts by monitoring POST requests to the vulnerable endpoint.
*   Monitor web server logs for suspicious POST requests to `existingUsernameCheck.php` as described in the attack chain to identify and investigate potential username enumeration attempts.
