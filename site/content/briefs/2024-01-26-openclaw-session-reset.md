---
title: OpenClaw Gateway Agent Session Reset Vulnerability
slug: 2024-01-26-openclaw-session-reset
description: OpenClaw versions prior to 2026.3.23 expose an administrative session reset vulnerability via the Gateway agent RPC, allowing attackers with `operator.write` privileges to reset sessions that should require `operator.admin`.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openclaw
  - session-reset
  - privilege-escalation
vendors:
  - OpenClaw
products:
  - OpenClaw
references:
  - https://github.com/advisories/GHSA-wq58-2pvg-5h4f
rules:
  - title: Detect OpenClaw Unauthorized Session Reset
    description: Detects unauthorized session reset attempts in OpenClaw by monitoring for requests to the /reset or /new endpoints from users with operator.write privileges.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Gateway Agent Reset Endpoint Access
    description: Detects access to the OpenClaw Gateway Agent's /reset endpoint.  This can be used to identify potential exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions before `v2026.3.23` contain a vulnerability in the Gateway agent RPC that allows users with `operator.write` privileges to perform actions that should require `operator.admin` privileges. Specifically, the `/reset` and `/new` endpoints within the Gateway agent RPC in `src/gateway/server-methods/agent.ts` do not properly enforce the `operator.admin` check before calling `performGatewaySessionReset(...)`. This oversight allows attackers with lower-level write access to reset administrative sessions. The vulnerability was reported by @smaeljaish771 and addressed in commit `50f6a2f136fed85b58548a38f7a3dbb98d2cd1a0`, which is included in releases `v2026.3.23` and later. Defenders should ensure they are running version `v2026.3.23` or later.

## Attack Chain

1. An attacker gains `operator.write` privileges to the OpenClaw Gateway.
2. The attacker crafts a malicious RPC request to the `/reset` or `/new` endpoint of the Gateway agent.
3. The attacker includes a specific `sessionKey` in the RPC request, targeting an administrator's session.
4. The Gateway agent, due to the vulnerability, incorrectly processes the request without verifying `operator.admin` privileges.
5. The `performGatewaySessionReset(...)` function is called, resetting the targeted administrator's session.
6. The administrator's session is terminated, potentially disrupting ongoing administrative tasks.
7. If the attacker can predict or obtain valid session keys, this can be repeated.

## Impact

Successful exploitation of this vulnerability allows an attacker with limited `operator.write` privileges to disrupt administrative operations by forcibly resetting administrator sessions. This can lead to denial of service for administrative functions, potentially impacting the overall stability and security of the OpenClaw environment. The exact number of affected installations is unknown, but all OpenClaw deployments running versions prior to `v2026.3.23` are susceptible.

## Recommendation

*   Upgrade OpenClaw to version `v2026.3.23` or later to patch the vulnerability.
*   Monitor OpenClaw Gateway logs for requests to `/reset` and `/new` endpoints originating from accounts with only `operator.write` privileges.  Deploy the Sigma rule `Detect OpenClaw Unauthorized Session Reset` to detect this activity.
*   Implement strict access control policies to minimize the number of accounts with `operator.write` privileges.
*   Enable detailed logging for the OpenClaw Gateway to facilitate incident investigation and response.
