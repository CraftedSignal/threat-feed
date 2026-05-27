---
title: affiliate-toolkit WordPress Plugin RCE via BladeOne Template Injection (CVE-2026-6169)
slug: 2026-05-affiliate-toolkit-rce
description: The affiliate-toolkit plugin for WordPress is vulnerable to remote code execution (CVE-2026-6169) due to the use of the BladeOne templating engine's runString() method, which allows authenticated attackers with Editor-level access or higher to execute arbitrary PHP code by injecting it into a plugin template.
date: "2026-05-27T08:20:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - rce
  - wordpress
  - affiliate-toolkit
  - template injection
vendors:
  - WordPress
products:
  - affiliate-toolkit plugin <= 3.8.5
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-6169
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6169
rules:
  - title: Detect CVE-2026-6169 Exploitation Attempt via HTTP POST
    description: Detects CVE-2026-6169 exploitation — HTTP POST requests to WordPress plugin with PHP code injection in cs-uri-query or cs-uri-stem, indicating a potential attempt to exploit the affiliate-toolkit RCE vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1505.003
    data_sources:
      - webserver
  - title: Detect CVE-2026-6169 Exploitation - eval() in BladeOne
    description: Detects CVE-2026-6169 — Monitors PHP process execution for the use of eval() function within the context of BladeOne templating engine calls, indicating potential exploitation of affiliate-toolkit plugin.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The affiliate-toolkit plugin, versions 3.8.5 and earlier, is susceptible to remote code execution (RCE) due to insecure use of the BladeOne templating engine. The `runString()` method compiles user-supplied template content into PHP code and executes it using `eval()`. Authenticated users with Editor-level privileges or higher can inject arbitrary PHP code into a plugin template. This allows attackers to gain full control of the affected WordPress server. This vulnerability exists because the plugin fails to sanitize or sandbox user-provided template content before execution, leading to arbitrary PHP execution.

## Attack Chain

1.  Attacker authenticates to the WordPress instance with Editor-level privileges or higher.
2.  Attacker navigates to the affiliate-toolkit plugin settings or template editor within the WordPress admin panel.
3.  Attacker injects malicious PHP code into a plugin template, leveraging the BladeOne templating engine. The malicious payload is crafted to execute system commands or establish a reverse shell.
4.  The plugin processes the template containing the injected PHP code using the BladeOne `runString()` method.
5.  The `runString()` method compiles the injected PHP code and executes it via `eval()` without proper sanitization.
6.  The attacker's injected PHP code executes on the server, allowing the attacker to perform actions such as creating new administrative users, modifying website content, or accessing sensitive data.
7.  The attacker may establish a persistent foothold on the server by writing a backdoor to the file system or modifying WordPress core files.

## Impact

Successful exploitation of CVE-2026-6169 allows an attacker to execute arbitrary code on the WordPress server, leading to complete system compromise. This could result in data theft, website defacement, denial of service, or further propagation of malware to visitors of the website. Given the widespread use of WordPress and the affiliate-toolkit plugin, a successful exploit could impact a significant number of websites and their users.

## Recommendation

*   Apply the latest update to the affiliate-toolkit plugin to patch CVE-2026-6169.
*   Deploy the Sigma rule "Detect CVE-2026-6169 Exploitation Attempt via HTTP POST" to identify potential exploitation attempts in web server logs.
*   Review and restrict user privileges within WordPress to minimize the impact of compromised accounts.
*   Monitor WordPress file system for unauthorized changes, especially within the `/wp-content/plugins/affiliate-toolkit/` directory, using a file integrity monitoring system, to detect potential backdoors or malicious file uploads.
