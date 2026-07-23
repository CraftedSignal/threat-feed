---
title: MountDev AI MCP Connector WordPress Plugin Vulnerability Allows Unauthenticated Admin Access (CVE-2026-15015)
slug: 2026-07-mountdev-ai-mcp-connector-auth-bypass
description: An authorization bypass vulnerability, CVE-2026-15015, in all versions up to 1.6.1 of the MountDev AI MCP Connector for WordPress plugin allows unauthenticated attackers to obtain an administrator-bound OAuth Bearer token by exploiting publicly accessible client registration and an unprotected authorization endpoint, granting full administrator-equivalent access to the plugin's tool surface and WordPress content.
date: "2026-07-23T10:20:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - authorization-bypass
  - cve
  - webserver
  - privilege-escalation
vendors:
  - MountDev AI
  - WordPress Foundation
products:
  - MountDev AI MCP Connector for WordPress plugin <= 1.6.1
  - WordPress
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to obtain an administrator-bound OAuth Bearer token via a self-registered client
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: granting full administrator-equivalent access to the plugin's MCP tool surface and all exposed WordPress content, users, and options.
    confidence_band: high
cves:
  - id: CVE-2026-15015
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15015
rules:
  - title: Detects CVE-2026-15015 Exploitation - MountDev AI MCP Connector Dynamic Client Registration
    description: Detects attempts to exploit CVE-2026-15015 by identifying suspicious POST requests to the MountDev AI MCP Connector's dynamic client registration endpoint with an attacker-controlled redirect_uri.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-15015 describes a critical authorization bypass vulnerability affecting all versions up to, and including, 1.6.1 of the MountDev AI MCP Connector for WordPress plugin. This flaw stems from inadequate verification of user authorization, enabling unauthenticated attackers to acquire an administrator-level OAuth Bearer token. Attackers can leverage a publicly accessible Dynamic Client Registration endpoint to register arbitrary OAuth clients with a controlled `redirect_uri`, then utilize an unprotected authorization endpoint to complete the OAuth flow without requiring any administrator interaction. This leads to full administrator-equivalent control over the plugin's MCP tool surface and, by extension, all exposed WordPress content, user data, and configuration options. The vulnerability carries a CVSS v3.1 Base Score of 9.8, indicating severe impact and ease of exploitation for any affected WordPress site.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress instance running the MountDev AI MCP Connector plugin.
2. The attacker accesses the publicly exposed Dynamic Client Registration endpoint provided by the plugin.
3. The attacker registers an arbitrary OAuth client by providing a malicious `redirect_uri` that they control.
4. The attacker then initiates an OAuth authorization request using the newly registered client, leveraging an unprotected authorization endpoint within the plugin.
5. The plugin processes the OAuth flow, completing it without requiring any legitimate administrator interaction or approval.
6. Upon successful completion of the OAuth flow, the attacker obtains a valid OAuth Bearer token.
7. This token is administrator-bound, granting the attacker full administrator-equivalent access to the plugin's MCP tool surface.
8. The attacker uses this access to modify or exfiltrate WordPress content, user data, and system options.

## Impact

A successful exploitation of CVE-2026-15015 grants unauthenticated attackers full administrative control over the affected WordPress installation via the MountDev AI MCP Connector. This allows for complete compromise of the website, including unauthorized access to sensitive data, modification or defacement of content, creation of new administrative users, and potential injection of malicious code. The high CVSS score of 9.8 reflects the ease of exploitation and the devastating consequences, posing a severe risk to data integrity, confidentiality, and availability for organizations utilizing the vulnerable plugin.

## Recommendation

* Immediately update the MountDev AI MCP Connector for WordPress plugin to a version patched against CVE-2026-15015.
* Deploy the provided Sigma rule to your SIEM to detect attempts at exploiting the Dynamic Client Registration endpoint.
* Review web server access logs for unusual POST requests to `/wp-json/mountdev-ai-mcp-connector/v1/client/register` or similar endpoints, particularly those containing suspicious `redirect_uri` parameters.
