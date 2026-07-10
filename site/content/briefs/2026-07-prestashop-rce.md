---
title: Unauthenticated PHP Object Injection in PrestaShop ps_facetedsearch Leads to RCE
slug: 2026-07-prestashop-rce
description: An unauthenticated PHP Object Injection vulnerability, tracked as CVE-2026-54159, affects the PrestaShop ps_facetedsearch module versions 3.0.0 through 4.0.3, allowing attackers to craft malicious serialized PHP objects in URL parameters that, upon deserialization, result in arbitrary file writes and remote code execution on the server.
date: "2026-07-10T20:37:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - php-object-injection
  - rce
  - webshell
  - prestashop
  - cve
  - web-exploitation
vendors:
  - PrestaShop
products:
  - ps_facetedsearch (3.0.0 through 4.0.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A PHP Object Injection vulnerability affects the PrestaShop module ps_facetedsearch... Exploitation is remote and unauthenticated, a single crafted front-office request is enough, and leads to remote code execution and full compromise of the shop and its server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: a gadget chain writes an arbitrary PHP file inside the module directory, which is then used as a webshell to run commands on the server.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: a gadget chain writes an arbitrary PHP file inside the module directory, which is then used as a webshell to run commands on the server.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-m5f5-28qr-9g9r
rules:
  - title: Detects CVE-2026-54159 Exploitation Attempt - PHP Object Injection Patterns
    description: Detects CVE-2026-54159 exploitation - HTTP requests to PrestaShop's ps_facetedsearch module containing suspicious PHP object serialization patterns in URL query parameters, indicating a PHP Object Injection attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical unauthenticated PHP Object Injection vulnerability (CVE-2026-54159) has been identified in the PrestaShop `ps_facetedsearch` module, affecting all versions from 3.0.0 up to and including 4.0.3. This vulnerability allows remote attackers to achieve full compromise of PrestaShop installations without authentication. The flaw arises from insufficient validation of slider filter values (such as price or weight) taken directly from the request URL. Attackers can inject a specially crafted serialized PHP object into these parameters, which is then stored in an internal cache. When the application later attempts to `unserialize()` this malicious object, it triggers a gadget chain that writes an arbitrary PHP file - effectively a webshell - into the module's directory. This webshell can then be used to execute arbitrary commands on the underlying server, leading to complete control over the shop and its hosting environment.

## Attack Chain

1. An attacker crafts a malicious serialized PHP object embedded within a slider filter (e.g., price or weight) value in a URL parameter.
2. The crafted URL is submitted via an unauthenticated GET request to the PrestaShop front-office, targeting the `ps_facetedsearch` module.
3. The `ps_facetedsearch` module processes the URL parameter, accepting the value without proper validation, and stores the malicious input in its internal filter-block cache.
4. At a later point, the application retrieves the cached value and performs a raw native `unserialize()` operation on the malicious PHP object.
5. This deserialization process triggers a pre-existing PHP gadget chain within the application's environment.
6. The activated gadget chain exploits its capabilities to write an arbitrary PHP file, serving as a webshell, into the `modules/ps_facetedsearch/` directory.
7. The attacker subsequently accesses the newly created webshell via HTTP requests, allowing for arbitrary command execution on the compromised server.
8. This leads to unauthenticated Remote Code Execution (RCE) and full compromise of the PrestaShop instance and its host server.

## Impact

The successful exploitation of CVE-2026-54159 results in unauthenticated Remote Code Execution (RCE) and a complete compromise of the affected PrestaShop shop and its hosting server. Any PrestaShop installation utilizing a vulnerable version of the `ps_facetedsearch` module (3.0.0 through 4.0.3) that exposes a filter template containing a slider filter (price or weight) is at risk. Attackers can gain full control, leading to data theft, website defacement, server-side malware deployment, and other malicious activities. The unauthenticated nature of the vulnerability means that no prior access or credentials are required, significantly broadening the attack surface.

## Recommendation

* Upgrade the `ps_facetedsearch` module to version 4.0.4 or higher immediately to remove the vulnerability.
* As an interim measure, remove price and weight slider filters from any filter templates exposed on the front office.
* Clear the faceted-search filter cache and audit the `modules/ps_facetedsearch/` directory for any unexpected or newly created PHP files.
* Deploy the `Detects CVE-2026-54159 Exploitation Attempt - PHP Object Injection Patterns` Sigma rule to your WAF or SIEM and configure it to block requests matching the specified PHP serialization patterns.
