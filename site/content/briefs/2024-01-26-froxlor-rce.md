---
title: Froxlor API Local File Inclusion leads to Remote Code Execution
slug: 2024-01-26-froxlor-rce
description: Froxlor is vulnerable to local file inclusion via path traversal in the `def_language` parameter of the API, leading to remote code execution as the web server user.
date: "2024-01-26T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - froxlor
  - rce
  - lfi
  - php
vendors:
  - Froxlor
products:
  - Froxlor
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1552
    technique_name: Unprotected Credentials
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-w59f-67xm-rxx7
rules:
  - title: Froxlor Suspicious DefLanguage Update
    description: Detects API requests to Customers.update or Admins.update with suspicious def_language parameters containing path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1552.001
    data_sources:
      - webserver
      - linux
  - title: Froxlor Malicious Lng File Creation
    description: Detects creation of .lng.php files containing PHP code in customer web directories. Indicates initial stage of the attack.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Froxlor, a server management panel, is vulnerable to a critical remote code execution (RCE) vulnerability due to insufficient validation of the `def_language` parameter in its API. An authenticated customer can exploit this vulnerability by injecting a path traversal sequence into the `def_language` setting via the `Customers.update` API endpoint. The injected path traversal allows an attacker to load and execute arbitrary PHP code outside of the intended language file directory. This vulnerability affects Froxlor versions 2.3.5 and earlier. Successful exploitation allows the attacker to execute arbitrary PHP code as the web server user, potentially leading to full server compromise. This issue stems from inconsistent validation between the web UI and the API, where the API lacks proper sanitization against path traversal.

## Attack Chain

1. Attacker gains valid customer credentials for a Froxlor panel.
2. Attacker uploads a malicious PHP file (e.g., `evil.lng.php`) containing code to execute arbitrary commands, to their web directory via FTP.
3. Attacker crafts an API request to the `Customers.update` endpoint, setting the `def_language` parameter to a path traversal sequence pointing to the malicious PHP file (e.g., `../../../../../var/customers/webs/customer1/evil`).
4. The Froxlor API stores the tainted `def_language` value in the database without proper validation.
5. Attacker triggers the vulnerability by making another API request (e.g., `Customers.get`).
6. The `ApiCommand::initLang()` function loads the malicious `def_language` value from the database.
7. `Language::setLanguage()` and `Language::loadLanguage()` functions are called, which construct a file path using the attacker-controlled value and attempts to load a PHP file.
8. The `require` statement within `Language::loadLanguage()` executes the malicious PHP code, granting the attacker RCE as the web server user (e.g., www-data).

## Impact

Successful exploitation allows an authenticated customer to execute arbitrary PHP code as the web server user. This can lead to: full server compromise by obtaining database credentials and accessing sensitive information, lateral movement to other customer environments within the shared hosting panel, persistent backdoors by modifying core system files or cron jobs, and data exfiltration, allowing the attacker to steal all hosted databases and email content. The vulnerable API is enabled by default.

## Recommendation

*   Apply the vendor-supplied patch described in the source URL to remediate the vulnerable API endpoint (https://github.com/advisories/GHSA-w59f-67xm-rxx7).
*   Deploy the Sigma rule `Froxlor_Suspicious_DefLanguage_Update` to detect attempts to exploit the vulnerable API endpoint.
*   Enable web server logging to facilitate detection of API requests with malicious `def_language` parameters.
*   Monitor the file system for creation of `.lng.php` files in customer web directories as part of the attack chain, using the Sigma rule `Froxlor_Malicious_Lng_File_Creation`.
