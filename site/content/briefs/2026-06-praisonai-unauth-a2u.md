---
title: PraisonAI A2U Incomplete Authentication Fix (GHSA-jxcw-qp4h-6jfq)
slug: 2026-06-praisonai-unauth-a2u
description: An incomplete fix in PraisonAI's `praisonai serve a2u` command leaves the A2U Agent-to-User event stream server unauthenticated by default, potentially exposing sensitive agent event streams to any attacker who can reach the server, bypassing intended authentication mechanisms for versions `4.5.115` to `4.6.60`.
date: "2026-06-18T15:00:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - incomplete-fix
  - authentication-bypass
  - api-server
  - misconfiguration
  - data-exposure
  - praisonai
vendors:
  - MervinPraison
products:
  - praisonai (>= 4.5.115, < 4.6.61)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
references:
  - https://github.com/advisories/GHSA-jxcw-qp4h-6jfq
rules:
  - title: Detect Unauthenticated PraisonAI A2U Subscription Attempt
    description: Detects unauthenticated HTTP POST requests to the /a2u/subscribe endpoint, indicating an attempt to bypass authentication for sensitive agent event streams in PraisonAI.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1210
    data_sources:
      - webserver
  - title: Detect PraisonAI A2U Server Started with Exposed Host
    description: Detects the execution of the `praisonai serve a2u` command with the `--host 0.0.0.0` argument, which can expose the A2U server to external access without explicit authentication configured, contributing to data exposure.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1210
    data_sources:
      - process_creation
      - linux
  - title: Detect Unauthenticated PraisonAI A2U Info or Events Access
    description: Detects unauthenticated HTTP GET requests to '/a2u/info' or '/a2u/events/{stream_name}' endpoints, indicating an attempt to access sensitive agent event stream metadata or subscribe to events without authentication in PraisonAI.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1560.001
    data_sources:
      - webserver
rules_count: 3
---

A critical vulnerability exists in PraisonAI, affecting versions `4.5.115` through `4.6.60`, stemming from an incomplete fix for a previously disclosed unauthenticated access issue (GHSA-f292-66h9-fpmf). When an operator starts the A2U (Agent-to-User) event stream server using the documented `praisonai serve a2u` CLI command without explicitly configuring the `A2U_AUTH_TOKEN` environment variable, the server runs without any authentication. This default behavior contradicts the secure-by-default posture implied by the previous fix and current documentation, allowing unauthenticated access to sensitive agent event streams such as responses, tool calls, thinking/progress events, and stream metadata. Attackers can leverage this oversight to gain unauthorized insight into agent activities and potentially exfiltrate sensitive operational data if the server is exposed on a network interface.

## Attack Chain

1.  An operator installs PraisonAI versions between `4.5.115` and `4.6.60`.
2.  The operator starts the A2U server using the command `praisonai serve a2u --host 0.0.0.0 --port 8002` (or similar) without setting the `A2U_AUTH_TOKEN` environment variable.
3.  The `_create_a2u_app()` function in `src/praisonai/praisonai/cli/features/serve.py` registers A2U routes.
4.  The `create_a2u_routes()` function in `src/praisonai/praisonai/endpoints/a2u_server.py` checks for `A2U_AUTH_TOKEN` via `os.environ.get()`.
5.  Since `A2U_AUTH_TOKEN` is not set, the authentication mechanism (`_authenticate_request()`) returns `None`, effectively disabling authentication for all A2U endpoints.
6.  An unauthenticated attacker makes an HTTP GET request to `/a2u/info`, `/a2u/subscribe`, or `/a2u/events/{stream_name}` on the exposed PraisonAI A2U server.
7.  The server responds with sensitive agent event stream data, including agent responses, tool calls, thinking/progress events, and stream metadata, without requiring any credentials.
8.  The attacker successfully exfiltrates sensitive operational data or gains intelligence on agent activities.

## Impact

Attackers who can reach an unauthenticated PraisonAI A2U server are able to subscribe to sensitive agent event streams without credentials. This exposed data includes agent responses, details of tool calls, internal thinking/progress events, and stream metadata. Organizations relying on PraisonAI and believing the previously announced fix or the secure-by-default documentation may inadvertently deploy the A2U server on network interfaces, exposing these streams. This could lead to the unauthorized disclosure of proprietary operational logic, sensitive internal data processed by agents, or intelligence on ongoing tasks, potentially compromising business operations, intellectual property, or client data.

## Recommendation

*   **Upgrade PraisonAI to a patched version**: Ensure all PraisonAI installations are updated to version `4.6.61` or later, as specified in the affected range `pip:praisonai >= 4.5.115, < 4.6.61`.
*   **Implement Authentication**: For any PraisonAI A2U server currently deployed, explicitly set the `A2U_AUTH_TOKEN` environment variable before starting the `praisonai serve a2u` command to enforce authentication.
*   **Deploy the Sigma rules**: Deploy the provided Sigma rules to detect unauthenticated access attempts to A2U endpoints in webserver logs.
*   **Review deployment configurations**: Audit existing `praisonai serve a2u` deployments to confirm that `--host 0.0.0.0` is not used without proper authentication enabled, or that network segmentation limits access to trusted internal hosts only.
