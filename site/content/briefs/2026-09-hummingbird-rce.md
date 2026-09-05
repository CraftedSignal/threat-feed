---
title: 'CVE-2026-83627: Unauthenticated RCE in Hummingbird WordPress Plugin'
slug: 2026-09-hummingbird-rce
description: An unauthenticated remote code execution vulnerability in the Hummingbird WordPress plugin allows attackers to inject and execute arbitrary PHP code via unsanitized cookie headers in the debug log.
date: "2026-09-05T07:29:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:wpmudev:hummingbird:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - rce
  - vulnerability
vendors:
  - WPMU DEV
products:
  - Hummingbird (<= 3.21.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for unauthenticated attackers to write arbitrary PHP into the log file... and execute it by requesting the file directly.
    confidence_band: high
cves:
  - id: CVE-2026-83627
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83627
rules:
  - title: Detects CVE-2026-83627 Exploitation - Direct Access to Hummingbird Log
    description: Detects direct HTTP requests to the Hummingbird debug log file, which indicates potential RCE exploitation or reconnaissance.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update Hummingbird plugin to version 3.21.1 or later.
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable up to 3.21.0.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /wp-content/wphb-logs/ at the webserver level.
      owner: IT Operations
      addresses: CVE-2026-83627
      evidence: Source notes file is web-accessible and designed to be protected.
---

The Hummingbird - Speed Optimization, Caching, Minify, Compress & CDN plugin for WordPress (versions <= 3.21.0) is vulnerable to unauthenticated remote code execution (RCE). The vulnerability originates in the log_msg() function within the core/modules/class-page-cache.php file. The plugin maintains a debug log at 'wp-content/wphb-logs/page-caching-log.php', which is designed to prevent direct execution via a '<?php die(); ?>' header. However, due to a namespace resolution error in the class_exists() check, the header is omitted when the log is generated during a front-end request. 

An attacker can leverage this flaw by sending a crafted HTTP request containing cookies prefixed with 'wphb_cache_'. Because these cookies are written to the debug log without sanitization, an attacker can inject arbitrary PHP code. Once the log file is updated or rotated - either through manual action, cache flushing, or the plugin's automatic daily cron - the malicious payload becomes active. A subsequent direct request to the log file triggers execution of the injected code, granting the attacker full remote code execution capabilities.

## Attack Chain

1. Attacker performs reconnaissance to identify WordPress sites running the vulnerable Hummingbird plugin.
2. Attacker verifies the target has the 'Page Caching' debug log feature enabled.
3. Attacker sends an HTTP request to the target site with a malicious payload embedded in a cookie named with the 'wphb_cache_' prefix.
4. The log_msg() function processes the request and writes the unauthenticated/unsanitized cookie content directly into the 'wp-content/wphb-logs/page-caching-log.php' file.
5. The plugin log-rotation or cache flush process executes, causing the log file to lose its protective PHP header due to the namespace resolution error.
6. Attacker sends a direct HTTP request to 'wp-content/wphb-logs/page-caching-log.php'.
7. The web server executes the injected PHP code contained within the log file.
8. Attacker achieves remote command execution on the underlying server.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary PHP code on the server hosting the WordPress instance. This can lead to full site takeover, data exfiltration, internal network lateral movement, or complete compromise of the web server infrastructure.

## Recommendation

Prioritize the immediate update of the Hummingbird plugin to version 3.21.1 or later to remediate CVE-2026-83627. If an immediate update is not possible, disable the 'Page Caching' debug log feature and ensure the 'wp-content/wphb-logs/' directory is restricted from direct web access via web server configuration (e.g., denying access in .htaccess or Nginx configuration files). Implement the webserver-based detection rule below to identify exploitation attempts targeting the log file endpoint.
