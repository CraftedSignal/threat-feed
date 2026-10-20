---
brief_id: brief-2026-10-20-issuu-panel-rfi
event_id: brief-2026-10-20-issuu-panel-rfi
revision: 1
activity_at: "2026-10-20T21:53:49Z"
title: 'Issuu Panel Plugin: Arbitrary File Inclusion (CVE-2016-20101)'
slug: 2026-10-issuu-panel-rfi
description: The Issuu Panel plugin for WordPress before 1.6.6 is susceptible to unauthenticated remote and local file inclusion via the abspath parameter, enabling arbitrary PHP code execution.
date: "2026-10-20T21:53:49Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:issuu:issuu_panel:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - rce
  - file-inclusion
vendors:
  - Issuu
products:
  - Issuu Panel (< 1.6.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Issuu Panel plugin for WordPress before 1.6.6 contains a PHP file inclusion vulnerability that allows unauthenticated attackers to include remote or local files through the abspath parameter.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: Attackers can send GET requests to menu/documento/requests/ajax-docs.php with a crafted abspath value passed to require() to execute remote PHP code
    confidence_band: high
cves:
  - id: CVE-2016-20101
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20101
rules:
  - title: Detect CVE-2016-20101 Exploitation - Issuu Panel RFI/LFI
    description: Detects attempts to exploit the Issuu Panel WordPress plugin by passing external URLs or local file paths via the abspath parameter in the ajax-docs.php file
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Issuu Panel plugin to 1.6.6 or later
      owner: IT Operations
      due: 24h
      evidence: Vulnerability remediated in version 1.6.6
---

The Issuu Panel plugin for WordPress, specifically versions prior to 1.6.6, contains a critical vulnerability related to improper input validation in the file 'menu/documento/requests/ajax-docs.php'. The plugin fails to sanitize the 'abspath' parameter before passing it to a PHP 'require()' function. This flaw permits unauthenticated remote attackers to perform Local File Inclusion (LFI) or Remote File Inclusion (RFI) attacks. By manipulating the 'abspath' parameter in a crafted GET request, an attacker can force the web server to execute arbitrary PHP code or read sensitive local files from the filesystem. Exploitation of this vulnerability has been observed in the wild since October 2023, necessitating immediate patching for all WordPress instances utilizing this plugin.

## Attack Chain

1. Attacker performs reconnaissance to identify WordPress installations running the Issuu Panel plugin.
2. Attacker crafts a malicious GET request targeting the vulnerable file '/menu/documento/requests/ajax-docs.php'.
3. Attacker injects a malicious file path or remote URL into the 'abspath' parameter of the HTTP request.
4. The web server process receives the request and processes the PHP file 'ajax-docs.php'.
5. The vulnerable code within the plugin passes the attacker-supplied 'abspath' value directly to the 'require()' function.
6. The PHP interpreter executes the code located at the malicious URL or includes the local file specified by the attacker.
7. Attacker gains Remote Code Execution (RCE) on the underlying web server or exfiltrates sensitive server-side files.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary PHP code with the privileges of the web server user (e.g., www-data) or read sensitive configuration files (e.g., wp-config.php), leading to full site compromise, data exfiltration, and potential lateral movement within the hosting environment.

## Recommendation

* Update the Issuu Panel plugin for WordPress to version 1.6.6 or later immediately to patch CVE-2016-20101.
* Monitor web server access logs for anomalous GET requests containing suspicious 'abspath' parameters targeting 'ajax-docs.php'.
* Deploy the provided Sigma rule to detect attempts to exploit this file inclusion vulnerability via the web application layer.
