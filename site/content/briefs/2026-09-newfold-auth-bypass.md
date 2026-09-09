---
title: Authentication Bypass in Newfold WordPress Plugins via wp-module-data
slug: 2026-09-newfold-auth-bypass
description: An authentication bypass vulnerability in the wp-module-data library used by multiple Newfold plugins allows unauthenticated attackers to forge administrative access tokens and take over WordPress sites.
date: "2026-09-09T10:50:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:newfold:crazy_domains:*:*:*:*:*:wordpress:*:*
  - cpe:2.3:a:newfold:wp_plugin_web:*:*:*:*:*:wordpress:*:*
  - cpe:2.3:a:newfold:hostgator:*:*:*:*:*:wordpress:*:*
  - cpe:2.3:a:newfold:bluehost:*:*:*:*:*:wordpress:*:*
tags:
  - web-application-vulnerability
  - wordpress
  - cve-2026-80099
vendors:
  - Newfold
products:
  - Crazy Domains (<= 2.5.2)
  - WP Plugin Web (<= 2.3.4)
  - WP Plugin Hostgator (<= 3.1.0)
  - WP Plugin Bluehost (<= 4.17.1)
  - wp-module-data (<= 2.9.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows unauthenticated attackers to forge a valid Bearer token and gain administrator privileges.
    confidence_band: high
cves:
  - id: CVE-2026-80099
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80099
rules:
  - title: Detect CVE-2026-80099 Exploitation - Unauthorized Administrative REST API Access
    description: Detects potential exploitation of CVE-2026-80099 by identifying suspicious REST API requests that bypass standard authentication mechanisms.
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
    - action: Patch affected plugins to versions clearing CVE-2026-80099
      owner: IT Operations
      due: 24h
      evidence: Source advisory for CVE-2026-80099
  mitigation_plan:
    - priority: immediate
      action: Apply WAF rules to block unauthenticated REST API write operations to sensitive endpoints
      owner: IT Operations
      addresses: CVE-2026-80099
      evidence: Vulnerability analysis indicates exploit path via REST API
---

Researchers have identified a critical authentication bypass vulnerability (CVE-2026-80099) affecting the `wp-module-data` library, which is bundled with several Newfold Digital WordPress plugins. The vulnerability is triggered when the `authenticate()` method - registered via the `rest_authentication_errors` filter - encounters a failure in `HiiveConnection::get_auth_token()`. Under these conditions, PHP type coercion causes the secret HMAC salt to collapse into a publicly known static constant. 

An unauthenticated attacker can control the remaining inputs required for the HMAC calculation, including the HTTP method, request URI, raw body, and the `X-Timestamp` header. This allows the attacker to compute a valid Bearer token offline. Once forged, the token permits the attacker to bypass authentication and invoke `wp_set_current_user()` as an administrator. This vulnerability grants attackers complete control over affected WordPress installations, enabling actions such as creating new administrative users or installing arbitrary malicious plugins, which effectively leads to total site compromise. The issue affects multiple plugins, including Crazy Domains, WP Plugin Web, Hostgator, and Bluehost.

## Impact

Successful exploitation leads to full administrator-level access to the vulnerable WordPress installation. Threat actors can use this access to exfiltrate database contents, deploy web shells for persistence, inject malicious scripts, or host phishing content. This affects all organizations relying on the specified versions of the affected Newfold plugins for their web infrastructure.

## Recommendation

Prioritized actions for security and IT teams:
- Immediately identify and audit all WordPress installations for the affected plugins: Crazy Domains (<= 2.5.2), WP Plugin Web (<= 2.3.4), Hostgator (<= 3.1.0), and Bluehost (<= 4.17.1).
- Update all instances of `wp-module-data` to a version beyond 2.9.4 and update associated plugins to the latest available patched versions.
- Until patching is possible, restrict access to the REST API endpoints associated with the vulnerable plugins using firewall rules or web application firewall (WAF) policies.
- Review WordPress user lists for any unauthorized administrative accounts created or modified since the release of this advisory.
