---
title: 'CVE-2026-8719: Privilege Escalation Vulnerability in The AI Engine WordPress Plugin'
slug: 2026-05-ai-engine-privesc
description: The AI Engine – The Chatbot, AI Framework & MCP for WordPress plugin is vulnerable to privilege escalation (CVE-2026-8719) due to missing capability enforcement, allowing authenticated users (Subscriber+) to invoke admin-level MCP tools and gain administrator privileges.
date: "2026-05-17T04:17:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - wordpress
  - cve
vendors:
  - WordPress
products:
  - The AI Engine – The Chatbot, AI Framework & MCP for WordPress plugin <= 3.4.9
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-8719
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8719
  - CVE-2026-8719
rules:
  - title: Detect AI Engine MCP Privilege Escalation Attempt
    description: Detects CVE-2026-8719 exploitation — Attempts to access admin-level MCP tools using OAuth tokens without proper authorization in The AI Engine WordPress plugin.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Unauthorized MCP Tool Invocation via HTTP POST
    description: Detects HTTP POST requests to MCP (Management Console Protocol) tool endpoints without prior authentication, indicating potential unauthorized access attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

The AI Engine – The Chatbot, AI Framework & MCP for WordPress plugin, version 3.4.9 and earlier, is vulnerable to a privilege escalation vulnerability (CVE-2026-8719). This flaw stems from the plugin's failure to properly enforce WordPress capabilities within the MCP OAuth bearer-token authorization path. Consequently, any user with a valid OAuth token, including those with Subscriber roles or higher, can bypass authorization checks intended for administrators. This vulnerability poses a significant risk, as it allows attackers to invoke admin-level MCP tools, effectively escalating their privileges to that of an Administrator. This can lead to complete compromise of the WordPress site.

## Attack Chain

1. An attacker registers as a user on the WordPress site, obtaining at least Subscriber-level privileges.
2. The attacker authenticates to the WordPress site and obtains a valid OAuth token.
3. The attacker crafts a malicious HTTP request targeting an admin-level MCP tool endpoint.
4. The attacker includes the valid OAuth token in the "Authorization: Bearer [token]" header of the crafted HTTP request.
5. Due to missing capability enforcement, the AI Engine plugin incorrectly validates the OAuth token as belonging to an administrator.
6. The plugin grants access to the admin-level MCP tool without verifying the user's actual role or capabilities.
7. The attacker successfully invokes the admin-level MCP tool, leveraging its functionality to modify site settings, install plugins, or inject malicious code.
8. The attacker escalates their privileges to Administrator, gaining full control over the WordPress site.

## Impact

Successful exploitation of CVE-2026-8719 allows any authenticated user (Subscriber+) to escalate their privileges to that of a WordPress Administrator. This grants the attacker complete control over the compromised website, including the ability to modify content, install malicious plugins, create new administrator accounts, and potentially compromise sensitive data stored within the WordPress database. The impact ranges from defacement and data theft to complete system compromise and denial of service for legitimate users.

## Recommendation

*   Upgrade The AI Engine – The Chatbot, AI Framework & MCP for WordPress plugin to a version higher than 3.4.9 to patch CVE-2026-8719.
*   Deploy the Sigma rule `Detect AI Engine MCP Privilege Escalation Attempt` to detect suspicious requests to MCP endpoints with OAuth tokens, based on HTTP logs.
*   Review user roles and capabilities within WordPress to identify and remove any potentially malicious accounts.
