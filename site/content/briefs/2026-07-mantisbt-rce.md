---
title: MantisBT Remote Code Execution via Class Hoisting (CVE-2026-49273)
slug: 2026-07-mantisbt-rce
description: A high-severity remote code execution vulnerability, CVE-2026-49273, affects MantisBT versions 2.28.3 and earlier, allowing an authenticated administrator to achieve arbitrary code execution as the web server user by leveraging PHP's class hoisting during the processing of non-string configuration values in `adm_config_set.php`.
date: "2026-07-15T16:53:52Z"
lastmod: "2026-07-15T18:58:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - web-application
  - php
  - class-hoisting
  - mantisbt
  - xss
  - web-vulnerability
vendors:
  - MantisBT
products:
  - MantisBT (<= 2.28.3)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can [...] achieving arbitrary code execution.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-v84x-qvhg-f36r
  - https://github.com/mantisbt/mantisbt/commit/78c0af63d1fe0118004744cab21ca3bf2cea0f5c
  - https://mantisbt.org/bugs/view.php?id=37122
  - https://github.com/advisories/GHSA-h2wf-967x-gxvw
  - https://mantisbt.org/bugs/view.php?id=37234
rules:
  - title: Detects CVE-2026-49273 Exploitation - MantisBT RCE via adm_config_set.php
    description: Detects attempts to exploit CVE-2026-49273 in MantisBT by identifying HTTP POST requests to `adm_config_set.php` that contain PHP class or function definitions within URL query parameters, indicating code injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-15T18:58:02Z"
    level: L2
    summary: 'merged source coverage: MantisBT Stored XSS Vulnerability via Crafted Image Filenames (CVE-2026-62944)'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-h2wf-967x-gxvw
---

A critical remote code execution vulnerability, tracked as CVE-2026-49273, has been discovered in MantisBT versions 2.28.3 and earlier. This flaw exists within the "Manage Configuration" feature (accessible via `adm_config_set.php`) which is part of the administrative web UI. The vulnerability arises when an authenticated administrator attempts to set a configuration value of a non-string type (such as an integer or float). Although the application uses `eval()` with a `return;` prefix to prevent immediate code execution, PHP's compile-time behavior of hoisting class and function declarations bypasses this safeguard. An attacker can craft a malicious input that defines a class, which is then hoisted and can hijack a legitimate class loaded later by PHP's autoloader, leading to arbitrary code execution as the web server user. This vulnerability specifically requires administrator access to the web UI; the REST API and its `ConfigsSetCommand` are not affected.

## Attack Chain

1. **Initial Access**: An attacker obtains valid administrator credentials for the MantisBT web UI, typically through phishing, credential stuffing, or other means.
2. **Access Configuration Interface**: The attacker logs into the MantisBT web UI and navigates to the "Manage Configuration" page (`adm_config_set.php`).
3. **Craft Malicious Payload**: The attacker prepares a PHP code payload that defines a malicious class, designed to exploit PHP's class hoisting mechanism.
4. **Inject Payload**: The attacker submits a POST request to `adm_config_set.php`, setting a configuration value to the malicious PHP class definition, ensuring it is treated as a non-string type.
5. **Server-Side Processing**: MantisBT's `ConfigParser -> Tokenizer` component processes the input, calling `eval()` on the provided configuration value.
6. **Class Hoisting Bypass**: Despite the `return;` prefix in the `eval()` call, PHP hoists the attacker-defined class at compile time.
7. **Class Hijacking and Execution**: The hoisted malicious class can then hijack a legitimate class that MantisBT subsequently attempts to load via its autoloader. This allows the attacker to execute arbitrary PHP code as the underlying web server user (e.g., `www-data`).
8. **Post-Exploitation**: The attacker gains full control over the MantisBT installation, potentially leading to data exfiltration, defacement, or further lateral movement within the network.

## Impact

Successful exploitation of CVE-2026-49273 results in remote code execution as the web server user, which typically has privileges to read, write, and execute files within the web root and associated directories. This could lead to a complete compromise of the MantisBT application, including unauthorized access to project data, user credentials, and sensitive bug reports. Attackers could also use this access as a foothold to compromise the underlying server or other systems within the network. While the vulnerability requires authenticated administrator access, the impact is severe due to the potential for full system compromise.

## Recommendation

* **Patch CVE-2026-49273**: Immediately update all MantisBT installations to version 2.28.4 or later by applying the patch from `https://github.com/mantisbt/mantisbt/commit/78c0af63d1fe0118004744cab21ca3bf2cea0f5c` to mitigate CVE-2026-49273.
* **Monitor Web Server Logs**: Deploy the provided Sigma rule to detect suspicious POST requests to `adm_config_set.php` containing PHP class or function definitions. Ensure web server logs capture `cs-uri-stem` and `cs-uri-query` for `webserver` log sources.
* **Review Administrator Activity**: Regularly audit logs for `adm_config_set.php` to identify unusual configuration changes, especially from unexpected IP addresses or at unusual times.
