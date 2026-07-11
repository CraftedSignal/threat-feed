---
title: Local File Inclusion Vulnerability in LA-Studio Element Kit for Elementor Plugin for WordPress
slug: 2026-07-la-studio-element-kit-lfi
description: A Local File Inclusion vulnerability exists in the LA-Studio Element Kit for Elementor plugin for WordPress, affecting all versions up to and including 1.6.1, which allows authenticated attackers with contributor-level access or higher to include and execute arbitrary .php files on the server due to improper path traversal handling and an easily bypassed extension check, leading to PHP code execution, access control bypass, and sensitive data exposure.
date: "2026-07-11T04:21:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - vulnerability
  - lfi
  - web
vendors:
  - LA-Studio
  - WordPress
products:
  - LA-Studio Element Kit for Elementor plugin for WordPress (<= 1.6.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The LA-Studio Element Kit for Elementor plugin for WordPress is vulnerable to Local File Inclusion
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: include and execute arbitrary .php files on the server, allowing the execution of any PHP code in those files.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: the extension check is trivially bypassed because the caller already appends the required extension to the traversal payload.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This can be used to bypass access controls, obtain sensitive data, or achieve code execution
    confidence_band: high
cves:
  - id: CVE-2026-15338
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15338
---

A significant Local File Inclusion (LFI) vulnerability, identified as CVE-2026-15338, has been discovered in the LA-Studio Element Kit for Elementor plugin for WordPress, impacting all versions up to and including 1.6.1. This flaw resides within the plugin's `get_type_template` function, which, when triggered by an authenticated attacker with contributor-level privileges or higher, permits the inclusion and execution of arbitrary `.php` files present on the server. The vulnerability is primarily due to the `wp_normalize_path` function failing to adequately resolve or reject path traversal sequences. Additionally, an existing extension check is rendered ineffective as the plugin itself appends the required `.php` extension to the attacker-supplied payload, simplifying the bypass. Successful exploitation enables PHP code execution, potentially leading to unauthorized access, sensitive data exposure, and further compromise of the WordPress environment.

## Attack Chain

1. **Initial Access via Authentication**: An attacker obtains valid credentials with contributor-level access or higher to a WordPress site running the vulnerable LA-Studio Element Kit plugin.
2. **Request Crafting**: The attacker crafts a malicious HTTP request designed to interact with the plugin's `get_type_template` function, typically through a WordPress AJAX endpoint (e.g., `/wp-admin/admin-ajax.php`).
3. **Path Traversal Insertion**: The malicious request includes a path traversal sequence (e.g., `../`, `..\\`) within a parameter that the `get_type_template` function processes, targeting a specific `.php` file on the server.
4. **Extension Bypass**: The attacker's payload leverages the plugin's behavior where it automatically appends the `.php` extension to the user-supplied path, effectively bypassing any basic extension validation.
5. **Vulnerability Trigger**: The `get_type_template` function calls `wp_normalize_path` which processes the supplied path but fails to neutralize the path traversal sequences, leading to the construction of an unintended file path.
6. **Code Execution**: The vulnerable function then includes and executes the arbitrary `.php` file specified by the attacker, allowing them to run PHP code with the privileges of the web server process.
7. **Impact Realization**: This unauthorized code execution enables the attacker to bypass access controls, exfiltrate sensitive data, or deploy further malicious payloads such as web shells, leading to complete system compromise.

## Impact

The successful exploitation of CVE-2026-15338 allows authenticated attackers to execute arbitrary PHP code on the compromised WordPress server. This capability can lead to a complete bypass of access controls, enabling unauthorized manipulation or destruction of website content, exfiltration of sensitive data including user credentials or database information, and potentially full compromise of the underlying server. The vulnerability carries a CVSS v3.1 Base Score of 7.5, reflecting its high severity and potential for significant impact, ranging from defacement to complete takeover of the affected WordPress installation and host system.

## Recommendation

* Patch CVE-2026-15338 by immediately updating the LA-Studio Element Kit for Elementor plugin to version 1.6.2 or later to mitigate the Local File Inclusion vulnerability.
* Monitor web server access logs for WordPress installations for suspicious HTTP requests to `/wp-admin/admin-ajax.php` or other plugin endpoints that contain path traversal sequences (`../`, `..\\`) in query parameters, particularly when attempting to include `.php` files, as this could indicate exploitation of CVE-2026-15338.
