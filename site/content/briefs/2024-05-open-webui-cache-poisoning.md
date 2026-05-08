---
title: Open WebUI Cross-Instance Cache Poisoning Vulnerability
slug: 2024-05-open-webui-cache-poisoning
description: Open WebUI versions up to 0.8.12 are vulnerable to cross-instance cache poisoning when multiple instances share a Redis backend, allowing an attacker with admin access on one instance to overwrite cache values used by other instances, leading to data exfiltration and prompt injection attacks.
date: "2024-05-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cache-poisoning
  - redis
  - open-webui
  - vulnerability
vendors:
  - Redis
products:
  - open-webui (<= 0.8.12)
  - Redis
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-3x8w-4f7p-xxc2
rules:
  - title: Detect Open WebUI Tool Server Configuration Change
    description: Detects changes to the 'tool_servers' key in Redis, indicating potential unauthorized modification of tool server configurations.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - redis
  - title: Detect Open WebUI Terminal Server Configuration Change
    description: Detects changes to the 'terminal_servers' key in Redis, indicating potential unauthorized modification of terminal server configurations.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - redis
rules_count: 2
---

Open WebUI, a web interface for LLMs, is susceptible to a cross-instance cache poisoning vulnerability (CVE-2026-44552) when multiple instances share a Redis backend. This issue stems from missing `REDIS_KEY_PREFIX` usage for the `tool_servers` and `terminal_servers` keys in `utils/tools.py`. Specifically, lines 841, 850, 976, and 986 do not utilize the key prefix. As a result, an attacker with admin privileges on one instance can overwrite the cache values used by other instances. This vulnerability affects the current main branch (commit `6fdd19bf1`) and likely all versions since the tool server/terminal server Redis cache was introduced. This is a critical issue because it undermines the multi-instance isolation that `REDIS_KEY_PREFIX` aims to provide, potentially impacting blue-green deployments, multi-region setups, and cluster topologies.

## Attack Chain

1. An attacker gains admin access to Open WebUI Instance A, either through legitimate means or by exploiting vulnerabilities like LDAP empty-password or stale-admin-role issues.
2. The attacker configures a malicious tool server on Instance A, pointing to `https://attacker-controlled.example.com/openapi.json`. This configuration triggers a write to the `tool_servers` Redis key without the `REDIS_KEY_PREFIX` (line 841 in `utils/tools.py`).
3. Users on Open WebUI Instance B attempt to query available tools. This action triggers a read from the same unprefixed `tool_servers` Redis key (line 850 in `utils/tools.py`).
4. Instance B retrieves the attacker's poisoned tool server list from Instance A, which now includes the attacker's server, possibly replacing legitimate tool servers.
5. A user on Instance B invokes a tool. The tool call payload, including chat content, user identity, and OAuth tokens, is sent to the attacker-controlled server.
6. The attacker's server responds with arbitrary tool outputs, which are then fed back into Instance B's LLM context.
7. The malicious tool output is treated as trusted data within Instance B's LLM, enabling prompt injection and misinformation delivery.
8. The attacker leverages prompt injection and misinformation delivery to further compromise Instance B and exfiltrate sensitive data.

## Impact

Successful exploitation of this vulnerability leads to cross-instance cache poisoning, where one instance's admin can affect all users of another instance sharing the same Redis backend. Sensitive data, including chat content and user identity, can be exfiltrated to an attacker-controlled server. Furthermore, the attacker can inject malicious content into the victim instance's LLM context, leading to prompt injection attacks. This undermines the intended isolation between Open WebUI instances and can lead to significant data breaches and system compromise. The vulnerability's silent failure mode makes detection difficult for victim instances.

## Recommendation

- Deploy the Sigma rule "Detect Open WebUI Tool Server Configuration Change" to monitor for unauthorized changes to the `tool_servers` key (rule below).
- Deploy the Sigma rule "Detect Open WebUI Terminal Server Configuration Change" to monitor for unauthorized changes to the `terminal_servers` key (rule below).
- Apply available patches or upgrades to Open WebUI to versions beyond 0.8.12 as soon as they are released to address CVE-2026-44552.
- Restrict admin access to Open WebUI instances and enforce strong password policies.
- Review and audit existing Open WebUI deployments to ensure proper configuration and security best practices.
