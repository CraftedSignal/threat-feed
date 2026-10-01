---
title: CVE-2026-19807 Privilege Escalation in ByteCoreStack MCP Connector for AI Tools
slug: 2026-10-bytecorestack-mcp-privesc
description: The ByteCoreStack MCP Connector for AI Tools plugin for WordPress is vulnerable to privilege escalation via insufficient meta key validation, allowing Subscriber-level users to escalate to Administrator.
date: "2026-10-01T08:39:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bytecorestack:mcp_connector_for_ai_tools:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - privilege-escalation
  - web-application
vendors:
  - ByteCoreStack
products:
  - MCP Connector for AI Tools (<= 1.2.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers with Subscriber-level access and above to elevate their privileges to Administrator.
    confidence_band: high
cves:
  - id: CVE-2026-19807
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19807
rules:
  - title: Detects CVE-2026-19807 Exploitation - Unauthorized User Meta Update
    description: Detects exploitation attempts targeting CVE-2026-19807 by looking for JSON-RPC requests containing restricted user meta keys like wp_capabilities or wp_user_level.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory all WordPress instances running ByteCoreStack MCP Connector
      owner: SOC
      due: 24h
      evidence: Plugin identified as vulnerable in NVD entry
  mitigation_plan:
    - priority: immediate
      action: Disable ByteCoreStack MCP Connector plugin until a vendor security update is verified
      owner: IT Operations
      addresses: CVE-2026-19807
      evidence: Source states plugin is vulnerable in all versions up to 1.2.3
---

The ByteCoreStack - MCP Connector for AI Tools plugin for WordPress, in all versions up to and including 1.2.3, contains a critical privilege escalation vulnerability. The flaw exists within the `execute_tool` function when handling the `wp_update_user_meta` MCP tool. The implementation relies on `current_user_can('edit_user', $uid)` for authorization, which, when the target user ID matches the caller ID, defaults to the 'read' primitive. Furthermore, the plugin utilizes an insufficient blocklist for user meta keys, explicitly blocking `user_pass`, `user_activation_key`, and `session_tokens`, but failing to protect `wp_capabilities` and `wp_user_level`. Authenticated users with Subscriber access can exploit this to overwrite their own meta keys, granting themselves Administrator-level privileges. This issue poses a severe risk to WordPress instances utilizing this AI-connector plugin, as it facilitates full site compromise through unauthorized administrative access.

## Impact

Successful exploitation of CVE-2026-19807 enables an authenticated Subscriber-level user to gain full Administrator control over the affected WordPress instance. This results in the potential for complete site takeover, including code execution via plugin installation, data exfiltration, and full database access. Given the nature of WordPress privileges, this vulnerability is critical for all installations currently using version 1.2.3 or earlier of the affected plugin.

## Recommendation

* Immediately audit current ByteCoreStack MCP Connector plugin versions and restrict usage of the plugin until a vendor patch addressing the improper meta key validation is applied.
* Monitor web server logs for suspicious requests to MCP JSON-RPC endpoints that include parameters containing 'wp_capabilities' or 'wp_user_level' meta keys.
* Enable security audit logging for user metadata updates to identify unauthorized elevation attempts.
