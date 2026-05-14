---
title: Open WebUI Chat Completion API Tool Restriction Bypass (CVE-2026-45350)
slug: 2026-05-open-webui-tool-bypass
description: Open WebUI versions prior to 0.8.6 contain a vulnerability in the chat completion API that allows attackers to bypass tool restrictions by invoking any server tool with elevated privileges by supplying the correct tool_id or tool_servers parameters; this issue is tracked as CVE-2026-45350.
date: "2026-05-14T20:26:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - cve-2026-45350
  - privilege escalation
  - web application
vendors:
  - Open WebUI
products:
  - open-webui (<= 0.8.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-4pcg-253r-rf9w
  - https://github.com/open-webui/open-webui/blob/a7271532f8a38da46785afcaa7e65f9a45e7d753/backend/open_webui/main.py#L1529
  - https://github.com/open-webui/open-webui/blob/a7271532f8a38da46785afcaa7e65f9a45e7d753/backend/open_webui/main.py#L1613-L1614
  - https://github.com/open-webui/open-webui/blob/a7271532f8a38da46785afcaa7e65f9a45e7d753/backend/open_webui/utils/middleware.py#L1394
  - https://github.com/open-webui/open-webui/blob/a7271532f8a38da46785afcaa7e65f9a45e7d753/backend/open_webui/models/tools.py#L139
  - https://github.com/modelcontextprotocol/servers/blob/main/src/fetch/README.md
  - https://github.com/open-webui/open-webui/commit/9b06fdc8fe1c933071610336be05f11e77e6c8eb
  - https://github.com/open-webui/open-webui/commit/4737e1f11
rules:
  - title: Detect Open WebUI Chat Completion API Tool Restriction Bypass
    description: Detects CVE-2026-45350 exploitation — Attempts to invoke the /api/chat/completions endpoint with tool_ids parameter indicating potential tool restriction bypass
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
  - title: Detect Open WebUI MCP Streamable HTTP Tool Configuration
    description: Detects creation of MCP Streamable HTTP external tools which can lead to malicious code execution
    platform: sigma
    severity: low
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI is vulnerable to a tool restriction bypass in its chat completion API. Specifically, versions 0.6.43 through 0.8.5 are affected. The vulnerability, identified as CVE-2026-45350, stems from a lack of proper permission checks when retrieving tools via the `get_tool_by_id` function. An attacker can exploit this by supplying arbitrary `tool_id` or `tool_servers` parameters through the chat completion API, thereby invoking restricted server tools with elevated privileges. This occurs because the authentication token stored on the server is used when invoking the tool, effectively granting the attacker server-level privileges. The issue was resolved in versions v0.7.0 and v0.8.6.

## Attack Chain

1. An attacker with low privileges gains access to an Open WebUI instance.
2. The attacker identifies a restricted tool configured within the Open WebUI instance.
3. The attacker crafts a malicious request to the `/api/chat/completions` endpoint.
4. The request includes a prompt designed to utilize the restricted tool.
5. The request contains the `tool_ids` parameter set to the ID of the restricted tool, or the `tool_servers` parameter, pointing to the restricted tool's server.
6. The `get_tool_by_id` function retrieves the tool without proper permission checks.
7. The server's authentication token is used to invoke the tool.
8. The restricted tool executes with server privileges, potentially leading to unauthorized actions.

## Impact

Successful exploitation of this vulnerability allows low-privilege users to bypass intended tool restrictions and execute privileged actions within the Open WebUI environment. This can lead to unauthorized data access, modification, or other malicious activities, effectively escalating the attacker's privileges and compromising the integrity of the system.

## Recommendation

*   Upgrade Open WebUI to version 0.8.6 or later to remediate CVE-2026-45350.
*   Deploy the provided Sigma rule `Detect Open WebUI Chat Completion API Tool Restriction Bypass` to identify attempts to exploit this vulnerability via HTTP requests to the `/api/chat/completions` endpoint.
*   Monitor web server logs for suspicious requests containing `tool_ids` parameters associated with restricted tools to detect potential exploitation attempts.
*   Review and enforce proper access controls for tools within Open WebUI to prevent unauthorized usage, in addition to patching.
