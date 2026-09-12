---
title: Local File Inclusion Vulnerability in GEO my WP WordPress Plugin
slug: 2026-09-geo-my-wp-lfi
description: The GEO my WP plugin for WordPress is vulnerable to unauthenticated local file inclusion (LFI) via the gmw_posts_locator_ajax_info_window_loader function, which can be escalated to remote code execution in specific PEAR-enabled environments.
date: "2026-09-12T09:19:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:geomywp:geo_my_wp:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - lfi
  - vulnerability
  - rce
vendors:
  - GEO my WP
products:
  - GEO my WP (<= 4.5.5.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for unauthenticated attackers to include and execute arbitrary .php files on the server.
    confidence_band: high
cves:
  - id: CVE-2026-85200
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85200
rules:
  - title: Detects CVE-2026-85200 Exploitation - LFI via gmw_posts_locator_ajax_info_window_loader
    description: Detects attempts to exploit Local File Inclusion in the GEO my WP plugin by identifying suspicious directory traversal characters in the associated AJAX loader query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch GEO my WP to a version later than 4.5.5.3
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-85200 advisory
  hunt_leads:
    - lead: Search web logs for requests to gmw_posts_locator_ajax_info_window_loader with path traversal patterns
      technique_id: T1203
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source states vulnerability is reachable via this function
  mitigation_plan:
    - priority: immediate
      action: Disable the plugin if patching is not immediately feasible
      owner: IT Operations
      addresses: CVE-2026-85200
      evidence: Vulnerability allows unauthenticated RCE
---

The GEO my WP plugin for WordPress (versions up to and including 4.5.5.3) contains a critical security flaw involving improper input validation within the gmw_posts_locator_ajax_info_window_loader function. This vulnerability enables unauthenticated attackers to perform Local File Inclusion (LFI). By manipulating input parameters, an attacker can force the application to include and execute arbitrary PHP files residing on the web server.

This flaw allows attackers to bypass standard access controls and potentially exfiltrate sensitive application data. Of particular concern is the escalation path in server configurations where the PEAR framework is installed with the register_argc_argv configuration enabled. In these environments, attackers can leverage the LFI vulnerability to inject and execute arbitrary PHP code, resulting in full remote code execution (RCE). Security teams should prioritize patching or disabling the vulnerable component immediately.

## Impact

Successful exploitation allows unauthenticated attackers to read sensitive local files, bypass application-level authentication, and achieve full remote code execution on the underlying server if specific PHP environment configurations are present. This impact covers all WordPress instances running GEO my WP version 4.5.5.3 or older.

## Recommendation

1. Upgrade the GEO my WP plugin to the latest patched version immediately.
2. Audit server-side PHP configurations, specifically the status of the PEAR library and the register_argc_argv setting, to reduce the risk of RCE escalation.
3. Deploy web application firewall (WAF) rules to detect and block abnormal directory traversal or file inclusion attempts targeting the gmw_posts_locator_ajax_info_window_loader function.
4. Enable and monitor server-side web access logs for anomalous HTTP requests targeting AJAX endpoints with parameter values containing directory navigation sequences (e.g., ../).
