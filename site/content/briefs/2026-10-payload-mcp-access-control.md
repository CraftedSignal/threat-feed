---
title: Improper Access Control in Payload CMS MCP Plugin
slug: 2026-10-payload-mcp-access-control
description: An improper access control vulnerability (CVE-2026-105806) in the @payloadcms/plugin-mcp package allows authenticated users to manage API keys across accounts, facilitating privilege escalation and account takeover.
date: "2026-10-06T18:48:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:payload:plugin_mcp:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - cms
  - web-application
vendors:
  - Payload
products:
  - plugin-mcp (>= 3.61.0, < 3.88.0)
cves:
  - id: CVE-2026-105806
references:
  - https://github.com/advisories/GHSA-2q76-m6w6-qgc6
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade @payloadcms/plugin-mcp to version 3.88.0 or later
      owner: IT Operations
      due: 24h
      evidence: Users should upgrade to @payloadcms/plugin-mcp version 3.88.0 or later.
  mitigation_plan:
    - priority: immediate
      action: Disable the MCP plugin or restrict API-key management access
      owner: IT Operations
      addresses: CVE-2026-105806
      evidence: Until then, disable the MCP plugin or restrict MCP API-key management to trusted users.
---

The @payloadcms/plugin-mcp package for Payload CMS is affected by an improper access control vulnerability, tracked as CVE-2026-105806, impacting versions 3.61.0 through 3.87.9. This vulnerability allows an already authenticated user to interact with and manage Model Context Protocol (MCP) API keys belonging to accounts other than their own. By manipulating requests to the API key management endpoints, an attacker can hijack these keys, potentially leading to unauthorized access, further privilege escalation, and full account takeover within the Payload CMS environment. The issue stems from insufficient validation of ownership or permission boundaries during API key management operations. Defenders should prioritize patching, as this flaw directly undermines the security boundaries between users in a multi-tenant or collaborative CMS deployment.

## Impact

The vulnerability allows unauthorized management of security credentials (API keys) across different user accounts within the same Payload CMS instance. If exploited, an attacker can gain control over administrative or higher-privileged API keys, leading to complete account takeover, exfiltration of sensitive CMS data, or unauthorized configuration changes. The impact is significant for organizations relying on the MCP plugin for automated workflows and integrations.

## Recommendation

- Upgrade the @payloadcms/plugin-mcp package to version 3.88.0 or later immediately to patch CVE-2026-105806.
- If immediate patching is not feasible, disable the MCP plugin functionality until the upgrade is performed.
- Audit logs for the API key management endpoints in Payload CMS to identify unauthorized access attempts or unusual patterns involving key manipulation from non-administrative users.
- Restrict access to MCP API-key management interfaces to a highly limited set of trusted users until the software is updated.
