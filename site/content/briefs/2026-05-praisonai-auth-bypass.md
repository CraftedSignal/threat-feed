---
title: PraisonAI Legacy API Server Authentication Bypass (CVE-2026-44338)
slug: 2026-05-praisonai-auth-bypass
description: PraisonAI ships a legacy Flask API server with authentication disabled by default, allowing any reachable caller to access `/agents` and trigger the configured `agents.yaml` workflow through `/chat` without providing a token (CVE-2026-44338).
date: "2026-05-11T13:57:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:praison:praisonai:*:*:*:*:*:*:*:*
tags:
  - authentication bypass
  - API
  - CVE-2026-44338
vendors:
  - PraisonAI
products:
  - PraisonAI (>= 2.5.6, <= 4.6.33)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-44338
    cvss: 7.3
    epss: 0.00056
references:
  - https://github.com/advisories/GHSA-6rmh-7xcm-cpxj
  - CVE-2026-44338
rules:
  - title: Detect Unauthenticated Access to PraisonAI Agents Endpoint
    description: Detects CVE-2026-44338 exploitation — GET requests to the /agents endpoint without authentication headers, indicating a potential authentication bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Unauthenticated Chat Request to PraisonAI API Server
    description: Detects CVE-2026-44338 exploitation — POST requests to the /chat endpoint without authentication headers, indicating a potential authentication bypass and workflow trigger attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

PraisonAI includes a legacy Flask API server (`src/praisonai/api_server.py`) that, by default, ships with authentication disabled. This is due to hardcoded values `AUTH_ENABLED = False` and `AUTH_TOKEN = None`, causing the `check_auth()` function to always return `True` and effectively bypass authentication checks on `/agents` and `/chat` endpoints. The affected versions range from v2.5.6 to 4.6.33, which is the current PyPI release as of May 1, 2026. The `serve agents` command is not affected, but the older `api_server.py` binds to 0.0.0.0:8080 by default, and the generated sample API deployment YAML recommends `host: 0.0.0.0` together with `auth_enabled: false`, further exacerbating the issue. This vulnerability, identified as CVE-2026-44338, allows unauthenticated access to sensitive functionality.

## Attack Chain

1. Target identifies a PraisonAI instance running the vulnerable legacy API server.
2. Target sends a GET request to `/agents` endpoint to enumerate available agents.
3. The API server, due to disabled authentication, grants access to the `/agents` endpoint without requiring any authentication credentials.
4. The server responds with agent metadata, revealing the configured `agents.yaml` file.
5. Target crafts a POST request to the `/chat` endpoint, including a `message` key in the JSON payload.
6. The API server processes the request, bypassing authentication, and executes the workflow defined in `agents.yaml` by calling `PraisonAI(agent_file="agents.yaml").run()`.
7. The API server returns the result of the `PraisonAI.run()` call to the unauthenticated attacker.
8. Depending on the configuration specified in agents.yaml, this can result in data exfiltration, code execution, or denial of service via resource exhaustion.

## Impact

Successful exploitation allows any attacker with network access to the vulnerable PraisonAI instance to enumerate configured agents, trigger workflows defined in `agents.yaml`, consume model/API quota, and potentially expose sensitive information. The impact is determined by the capabilities defined in the `agents.yaml` file, but the authentication bypass itself is unconditional in the shipped legacy server. This vulnerability affects PraisonAI versions 2.5.6 through 4.6.33.

## Recommendation

*   Deploy the Sigma rule "Detect Unauthenticated Access to PraisonAI Agents Endpoint" to detect unauthenticated access attempts to the `/agents` endpoint within your web server logs.
*   Deploy the Sigma rule "Detect Unauthenticated Chat Request to PraisonAI API Server" to identify unauthorized requests being made to the `/chat` endpoint to trigger workflow executions.
*   Upgrade PraisonAI to a version that addresses CVE-2026-44338 or migrate to the newer `serve agents` command which defaults to binding on localhost and supports API keys.
*   If upgrading is not immediately feasible, ensure the legacy API server's `AUTH_ENABLED` setting is set to `True` and configure a strong `AUTH_TOKEN` to mitigate the unauthenticated access vulnerability.
*   Review and restrict network access to the legacy API server to minimize the attack surface and prevent unauthorized external access to the vulnerable endpoints.
