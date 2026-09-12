---
title: Remote Code Execution in The Events Calendar WordPress Plugin
slug: 2026-09-the-events-calendar-rce
description: The Events Calendar plugin for WordPress is vulnerable to unauthenticated remote code execution via a flaw in the parse_array function that allows attackers to bypass security checks through crafted widget block comments.
date: "2026-09-12T09:18:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:modern_tribe:the_events_calendar:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - cve
  - rce
  - vulnerability
vendors:
  - Modern Tribe
products:
  - The Events Calendar (<= 6.17.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to execute code on the server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This is due to insufficient validation... allowing a plain-array payload to reach the callable-invocation sink.
    confidence_band: high
cves:
  - id: CVE-2026-78159
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78159
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade The Events Calendar plugin to the latest secure version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-78159 mitigation
  mitigation_plan:
    - priority: immediate
      action: Disable comments on tribe_events post types
      owner: IT Operations
      addresses: CVE-2026-78159
      evidence: Exploitation requires that the targeted site has comments enabled on tribe_events posts
---

The Events Calendar plugin for WordPress is vulnerable to an unauthenticated Remote Code Execution (RCE) flaw, tracked as CVE-2026-78159. This vulnerability affects all versions up to and including 6.17.3. The flaw resides within the `Element_Classes::parse_array` method, which fails to adequately validate the `widget 'classes'` map. 

An attacker can supply a specially crafted `wp:legacy-widget` block within a comment on a `tribe_events` post. This payload bypasses the `is_safe_widget_instance()` object validation check. When the WordPress `do_blocks()` function processes the page content - specifically including the comment section - it triggers a callable-invocation sink in the `parse_array` function, enabling arbitrary PHP code execution. This vulnerability is critical as it requires no authentication to exploit, relying only on the presence of comments on events posts.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary code on the underlying web server hosting the WordPress site. This can lead to full site compromise, data exfiltration, and the installation of persistent backdoors. Given the widespread use of The Events Calendar plugin, this vulnerability poses a high risk to organizations hosting event-driven content on WordPress.

## Recommendation

Prioritize the immediate update of The Events Calendar plugin to the latest version (patching CVE-2026-78159). For instances where immediate patching is not possible, disable comments on all `tribe_events` post types to break the exploitation vector. Monitor web server logs for HTTP POST requests directed at comment submission endpoints that contain serialized or legacy widget-related strings if WAF virtual patching is required.
