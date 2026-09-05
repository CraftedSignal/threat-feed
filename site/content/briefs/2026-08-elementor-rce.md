---
title: Unauthenticated Remote Code Execution in Elementor Pro
slug: 2026-08-elementor-rce
description: Elementor Pro versions 4.2.1 and below contain a critical file upload vulnerability (CVE-2026-32475) that allows unauthenticated attackers to achieve remote code execution by bypassing extension validation.
date: "2026-08-20T07:09:14Z"
lastmod: "2026-09-05T13:18:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - wordpress
  - remote-code-execution
  - cve-2026-32475
vendors:
  - Elementor
  - WordPress
products:
  - Elementor Pro (4.2.1)
  - WordPress Core (7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The flaw lives in the Forms module's File Upload field... an unauthenticated attacker skips the extension blocklist entirely and writes a PHP file into a public directory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Successful exploitation of the flaw could allow an attacker to upload arbitrary files, including PHP scripts, that could then be used to achieve remote code execution.
    confidence_band: high
references:
  - https://thehackernews.com/2026/08/elementor-pro-flaw-could-let.html
  - https://www.securityweek.com/elementor-pro-wordpress-plugin-vulnerability-exploited-to-hack-sites/
rules:
  - title: Detect CVE-2026-32475 Exploitation - PHP File Upload in Elementor Forms
    description: Detects the creation of .php files in the Elementor forms upload directory which is indicative of CVE-2026-32475 exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Elementor Pro to version 4.2.2 or higher.
      owner: IT Operations
      due: 24h
      evidence: The update (version 4.2.2) was released on August 19 to address the flaw.
  hunt_leads:
    - lead: Check web server logs for HTTP POST requests to the site targeting file upload endpoints with .php extensions.
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: By submitting two file parts for the same field, an unauthenticated attacker skips the extension blocklist.
  mitigation_plan:
    - priority: immediate
      action: Remove unauthorized .php files from /wp-content/uploads/elementor/forms/.
      owner: IT Operations
      addresses: CVE-2026-32475
      evidence: The uploaded file is written as 'wp-content/uploads/elementor/forms/<uniqid>.php'.
updates:
  - at: "2026-09-05T13:18:59Z"
    level: L1
    summary: new IOCs
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/elementor-pro-wordpress-plugin-vulnerability-exploited-to-hack-sites/
---

Security researchers have identified a critical vulnerability, tracked as CVE-2026-32475, affecting the Elementor Pro WordPress plugin. The flaw resides in the Forms module's File Upload field, where an improper validation sequence allows attackers to bypass extension blocklists. By submitting two file parts for the same field, an unauthenticated attacker can effectively neutralize the extension check and move a malicious PHP file into a public directory. The resulting file is written to 'wp-content/uploads/elementor/forms/&lt;uniqid>.php'. 

Successful exploitation allows for unauthenticated remote code execution. The vulnerability impacts all plugin versions up to and including 4.2.1. This is particularly dangerous due to the ubiquity of Elementor Form widgets with file upload functionality enabled across WordPress installations. Furthermore, a secondary, distinct vulnerability in WordPress core (CVE-2026-65640) was disclosed, which allows for RCE via malicious Postscript files, though this requires higher-privileged access compared to the Elementor flaw.

## Attack Chain

1. Attacker identifies a WordPress site running a vulnerable version of Elementor Pro (<= 4.2.1).
2. Attacker locates a public-facing page containing an Elementor Form widget with a File Upload field.
3. Attacker crafts a multipart HTTP request targeting the File Upload field.
4. Attacker submits the request containing two file parts for the same field to trigger the validation logic discrepancy.
5. The plugin fails to correctly validate the second file part, allowing the PHP file to pass the blocklist check.
6. The application writes the malicious PHP script to the public web-accessible directory 'wp-content/uploads/elementor/forms/'.
7. Attacker requests the newly created .php file via a direct HTTP GET request.
8. Web server executes the attacker's script, resulting in arbitrary code execution.

## Impact

Successful exploitation results in full unauthenticated remote code execution on the underlying web server. This allows attackers to gain persistent access, exfiltrate site data, and potentially pivot into the internal network. Given the high prevalence of Elementor Pro, the potential victim count is significant across various sectors hosting WordPress-based web applications.

## Recommendation

* Immediately update Elementor Pro to version 4.2.2 or higher to address CVE-2026-32475.
* Audit 'wp-content/uploads/elementor/forms/' for any unauthorized .php files.
* Update WordPress core to version 7.0.4 or higher to mitigate the secondary RCE risk associated with CVE-2026-65640.
* Deploy the provided Sigma rule to detect unexpected .php file creation within the Elementor forms directory.
