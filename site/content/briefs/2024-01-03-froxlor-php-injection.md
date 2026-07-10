---
title: Froxlor PHP Code Injection via Unescaped Single Quotes in userdata.inc.php
slug: 2024-01-03-froxlor-php-injection
description: Froxlor is vulnerable to PHP code injection due to unescaped single quotes in the userdata.inc.php generation via the MysqlServer API, where an administrator with `change_serversettings` permission can inject arbitrary PHP code, leading to arbitrary OS command execution as the web server user.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - froxlor
  - php-injection
  - webserver
vendors:
  - Froxlor
products:
  - Froxlor
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
references:
  - https://github.com/advisories/GHSA-gc9w-cc93-rjv8
rules:
  - title: Detect Froxlor MysqlServer API Abuse
    description: Detects suspicious API requests to the Froxlor API endpoint `/api.php` that could indicate abuse of the MysqlServer API to inject PHP code.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Froxlor PHP Code Injection in userdata.inc.php
    description: Detects potential PHP code injection attempts by monitoring file writes to `userdata.inc.php` containing suspicious code patterns.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Froxlor versions 2.3.5 and earlier contain a PHP code injection vulnerability in `userdata.inc.php` due to improper handling of single quotes. An administrator with the `change_serversettings` permission can inject arbitrary PHP code through the `MysqlServer.add` or `MysqlServer.update` API endpoints. The vulnerability exists because the `PhpHelper::parseArrayToString()` function writes string values into single-quoted PHP string literals without escaping single quotes.  Specifically, the `privileged_user` parameter, which lacks input validation, is written to `lib/userdata.inc.php`. Since this file is included on every request via `Database::getDB()`, a successful exploit results in arbitrary PHP code execution as the web server user. This allows attackers to compromise the server, exfiltrate data, move laterally, establish persistent backdoors, or cause denial of service.

## Attack Chain

1. An administrator with `change_serversettings` permission authenticates to the Froxlor API.
2. The attacker sends a POST request to `api.php` with the command `MysqlServer.add` or `MysqlServer.update`, injecting PHP code into the `privileged_user` parameter.
3. The API endpoint `lib/Froxlor/Api/Commands/MysqlServer.php` processes the request, calling `PhpHelper::parseArrayToPhpFile()` through `generateNewUserData()`.
4. `PhpHelper::parseArrayToString()` at `lib/Froxlor/PhpHelper.php` formats the injected code without proper escaping, writing it into the 'user' key within an array.
5. The array is then written to `lib/userdata.inc.php` using `file_put_contents()`.
6. Subsequent HTTP requests to the Froxlor panel trigger `Database::getDB()` at `lib/Froxlor/Database/Database.php`.
7. `Database::getDB()` includes `lib/userdata.inc.php` using `require`, resulting in the execution of the injected PHP code.
8. The injected code executes commands as the web server user, allowing the attacker to achieve their objectives such as data exfiltration or establishing a persistent backdoor.

## Impact

Successful exploitation allows an admin with `change_serversettings` permissions to achieve arbitrary OS command execution as the web server user. This can lead to full server compromise, allowing attackers to read all hosted customer data, including database credentials and TLS private keys.  Attackers can also use the compromised server for lateral movement, accessing MySQL databases and other internal systems. The injected code persists on every request, providing a persistent backdoor.  Malformed PHP can also lead to a denial of service condition, disrupting the entire Froxlor panel.  The vulnerability affects Froxlor installations up to and including version 2.3.5.

## Recommendation

*   Apply the patch provided in the advisory that escapes single quotes in `PhpHelper::parseArrayToString()` before interpolating values, specifically by escaping backslashes and then single quotes.
*   Alternatively, use nowdoc syntax for all string values in `PhpHelper::parseArrayToString()` as defense-in-depth to completely prevent injection.
*   Deploy the Sigma rule `Detect Froxlor MysqlServer API Abuse` to identify potential exploitation attempts by monitoring API requests to the `/api.php` endpoint.
*   Enable webserver logging to detect the execution of injected php code, and tune the `Detect Froxlor PHP Code Injection in userdata.inc.php` Sigma rule.
*   Restrict and monitor `change_serversettings` permissions to reduce the attack surface.
