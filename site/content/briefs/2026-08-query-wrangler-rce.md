---
title: Remote Code Execution in Query Wrangler WordPress Plugin
slug: 2026-08-query-wrangler-rce
description: An unauthenticated-accessible AJAX handler in Query Wrangler versions 1.5.57 and below allows authenticated attackers to perform remote code execution via object injection and callback manipulation.
date: "2026-08-16T06:24:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - rce
  - plugin-vulnerability
vendors:
  - WordPress
products:
  - Query Wrangler (1.5.57)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Query Wrangler plugin for WordPress is vulnerable to Remote Code Execution... via the 'options' parameter.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The options... are passed directly to call_user_func_array() ... making it possible for authenticated attackers... to execute code on the server.
    confidence_band: high
cves:
  - id: CVE-2026-14498
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14498
rules:
  - title: Detect CVE-2026-14498 Exploitation - Query Wrangler RCE via AJAX
    description: Detects exploitation attempts against the Query Wrangler plugin where an AJAX request calls the vulnerable qw_form_ajax handler.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Query Wrangler to the version resolving CVE-2026-14498
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  hunt_leads:
    - lead: Search web logs for action=qw_form_ajax requests
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this specific handler as the entry point
  mitigation_plan:
    - priority: immediate
      action: Disable the Query Wrangler plugin until patching is completed
      owner: IT Operations
      addresses: CVE-2026-14498
      evidence: Plugin RCE vulnerability
---

The Query Wrangler plugin for WordPress, in versions up to and including 1.5.57, contains a critical Remote Code Execution (RCE) vulnerability identified as CVE-2026-14498. The flaw resides in the wp_ajax_qw_form_ajax handler, which processes requests without performing nonce verification or capability checks. An attacker with minimal privileges (subscriber level) can manipulate the 'options' parameter to inject malicious query configurations. Because these options are passed directly to the PHP call_user_func_array() function with insufficient validation beyond a function_exists() check, an attacker can trigger the execution of arbitrary server-side functions. This vulnerability is particularly dangerous because the query_id used in the handler is an enumerable integer, making it trivial for an attacker to identify an existing target row in the database and execute the exploit payload.

## Impact

Successful exploitation of CVE-2026-14498 grants an attacker the ability to execute arbitrary PHP code on the underlying web server. This can lead to full site compromise, data exfiltration, and lateral movement within the hosting environment. While the vulnerability requires subscriber-level authentication, the low barrier to entry and the ease of identifying targets via query_id enumeration significantly increase the risk profile for WordPress installations running this plugin.

## Recommendation

- Upgrade the Query Wrangler plugin to the latest version immediately to remediate CVE-2026-14498.
- Review web server access logs for anomalous POST requests directed at wp-admin/admin-ajax.php involving the qw_form_ajax action.
- Audit subscriber-level account activity for patterns of repeated requests targeting sequential query_id integers.
- Apply the following webserver detection logic to identify potential exploitation attempts in environment logs.
