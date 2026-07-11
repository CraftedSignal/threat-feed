---
title: Remote Code Execution in WP Ultimate CSV Importer WordPress Plugin
slug: 2026-07-rce-wp-ultimate-csv-importer
description: The WP Ultimate CSV Importer - WordPress Import & Export for CSV, XML & Excel plugin for WordPress, versions up to and including 8.0.1, is vulnerable to Remote Code Execution due to missing capability checks on specific AJAX handlers and exposure of the plugin's nonce, allowing authenticated attackers with subscriber-level access to execute arbitrary code on the server.
date: "2026-07-11T04:20:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - rce
  - cve
  - network
vendors:
  - WP Ultimate CSV Importer
products:
  - WP Ultimate CSV Importer – WordPress Import & Export for CSV, XML & Excel plugin (<= 8.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The WP Ultimate CSV Importer – WordPress Import & Export for CSV, XML & Excel plugin for WordPress is vulnerable to Remote Code Execution... allowing a Subscriber to install the Import WooCommerce add-on, persist attacker-controlled PHP expressions
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: trigger evaluation via eval() in ImportHelpers::get_meta_values(). This makes it possible for authenticated attackers... to execute code on the server.
    confidence_band: high
cves:
  - id: CVE-2026-13353
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13353
rules:
  - title: Detects CVE-2026-13353 Exploitation - RCE via WP Ultimate CSV Importer Plugin
    description: Detects CVE-2026-13353 exploitation attempts where authenticated attackers abuse specific AJAX handlers in the WP Ultimate CSV Importer plugin to inject and execute PHP code via the 'MappedFields' parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.008
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical remote code execution (RCE) vulnerability, identified as CVE-2026-13353, exists in the WP Ultimate CSV Importer - WordPress Import & Export for CSV, XML & Excel plugin for WordPress, affecting all versions up to and including 8.0.1. This flaw stems from a lack of capability checks on AJAX handlers for `install_addon`, `saveMappedFields`, and `StartImport`, coupled with the exposure of the plugin's nonce to any authenticated user. This combination allows authenticated attackers, even with low-privileged subscriber-level access, to leverage the vulnerability. By installing the Import WooCommerce add-on, injecting malicious PHP expressions into the `MappedFields` parameter, and triggering its evaluation via the `eval()` function within `ImportHelpers::get_meta_values()`, adversaries can achieve full remote code execution on the compromised server. This poses a significant risk to WordPress installations using the vulnerable plugin, potentially leading to website defacement, data exfiltration, or further network penetration.

## Attack Chain

1. An authenticated attacker, with subscriber-level access or higher, logs into the WordPress site.
2. The attacker loads any administrative page to retrieve the plugin's nonce, which is exposed to all authenticated users.
3. The attacker sends an AJAX request to the `install_addon` handler, bypassing capability checks due to the vulnerability, to install the Import WooCommerce add-on.
4. The attacker sends another AJAX request to the `saveMappedFields` handler, also lacking proper capability checks, to inject and persist attacker-controlled PHP expressions into the `MappedFields` parameter.
5. The attacker initiates an import process by sending a request to the `StartImport` AJAX handler.
6. The `StartImport` handler, lacking capability checks, processes the request, which subsequently calls `ImportHelpers::get_meta_values()`.
7. The `eval()` function within `ImportHelpers::get_meta_values()` evaluates the previously injected PHP expressions.
8. The attacker's PHP code is executed on the server, resulting in remote code execution and full control over the compromised WordPress installation.

## Impact

Successful exploitation of CVE-2026-13353 leads to arbitrary remote code execution on the affected WordPress server. This allows attackers to completely compromise the website, leading to potential data breaches, website defacement, injection of malicious content, or further penetration into the hosting environment. Organizations using the vulnerable plugin could face significant financial and reputational damage due to loss of data integrity, confidentiality, and availability. The vulnerability has a CVSS v3.1 Base Score of 8.8 (High), indicating a severe risk.

## Recommendation

* Patch CVE-2026-13353 by updating the WP Ultimate CSV Importer - WordPress Import & Export for CSV, XML & Excel plugin to a version higher than 8.0.1 immediately.
* Deploy the Sigma rule "Detects CVE-2026-13353 Exploitation - RCE via WP Ultimate CSV Importer Plugin" to your SIEM for detection of exploitation attempts.
* Monitor web server logs (category `webserver`) for suspicious requests to `admin-ajax.php` containing `action=install_addon`, `action=saveMappedFields`, or `action=StartImport` alongside potential PHP code in the `MappedFields` parameter.
