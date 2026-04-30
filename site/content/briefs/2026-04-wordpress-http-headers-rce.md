---
title: WordPress HTTP Headers Plugin Remote Code Execution via File Path Manipulation (CVE-2026-4132)
slug: 2026-04-wordpress-http-headers-rce
description: The HTTP Headers WordPress plugin is vulnerable to remote code execution (RCE) due to insufficient validation of the htpasswd file path and lack of sanitization of the username, allowing authenticated administrators to write arbitrary code to the server.
date: "2026-04-22T09:16:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - rce
  - plugin
  - cve-2026-4132
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1565
    technique_name: Data Manipulation
cves:
  - id: CVE-2026-4132
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4132
rules:
  - title: Detect PHP File Creation in Web Directories
    description: Detects the creation of PHP files in common web directories by the web server process, potentially indicating malicious file upload or RCE attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1565
    data_sources:
      - file_event
      - linux
  - title: Detect Unsanitized Username Injection in HTTP Headers Plugin htpasswd File
    description: Detects modifications to the .htpasswd file with usernames containing PHP tags, potentially indicating a RCE attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1565
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The HTTP Headers plugin for WordPress, versions up to and including 1.19.2, is vulnerable to remote code execution (RCE) due to a file path manipulation vulnerability (CVE-2026-4132). This vulnerability stems from the plugin's insufficient validation of the 'hh_htpasswd_path' option, which controls the location of the .htpasswd file. Furthermore, the 'hh_www_authenticate_user' option, used for setting the username for HTTP Basic Authentication, lacks proper sanitization. This allows attackers with administrator privileges to specify an arbitrary file path for the htpasswd file and inject unsanitized content into it. By crafting a malicious username containing PHP code and setting the htpasswd path to a web-accessible directory, an attacker can execute arbitrary code on the server. This exploit requires administrator-level access to the WordPress dashboard.

## Attack Chain

1. The attacker authenticates to the WordPress dashboard with administrator privileges.
2. The attacker navigates to the HTTP Headers plugin settings page.
3. The attacker modifies the 'hh_htpasswd_path' option, setting it to a web-accessible directory (e.g., `/var/www/html/wp-content/uploads/.shell.php`).
4. The attacker modifies the 'hh_www_authenticate_user' option, injecting PHP code into the username field (e.g., `<?php system($_GET['cmd']); ?>`).
5. The `apache_auth_credentials()` function uses sprintf to combine the malicious username with a SHA hash, creating a crafted htpasswd entry.
6. The `update_auth_credentials()` function then writes the crafted content, including the injected PHP code, to the attacker-controlled file path using `file_put_contents()`.
7. The attacker accesses the newly created PHP file via a web browser (e.g., `http://example.com/wp-content/uploads/.shell.php?cmd=id`).
8. The injected PHP code executes, allowing the attacker to run arbitrary commands on the server.

## Impact

Successful exploitation of this vulnerability grants the attacker remote code execution on the affected WordPress server. This can lead to complete compromise of the server, including data theft, website defacement, malware deployment, and further attacks against internal networks. Given the widespread use of WordPress and its plugins, a successful exploit could impact a large number of websites and organizations.

## Recommendation

*   Immediately update the HTTP Headers plugin to a patched version (if available) to remediate CVE-2026-4132.
*   Monitor web server logs for requests to unusual file paths that match the 'hh_htpasswd_path' setting specified in the plugin configuration to detect potential exploitation attempts.
*   Implement the Sigma rule to detect file creation events in web-accessible directories with PHP extensions that are triggered by the web server process.
*   Restrict access to the WordPress administrator dashboard to only trusted individuals and enforce strong password policies to prevent unauthorized access to plugin settings.
