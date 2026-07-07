---
title: OpenClaw Trusted-proxy Control UI Privilege Escalation (GHSA-qjpc-qf9m-xwmr)
slug: 2026-07-openclaw-privesc
description: A vulnerability in OpenClaw's trusted-proxy Control UI mode allows an unpaired or restricted trusted-proxy client to gain temporary `operator.admin` authority by declaring elevated WebSocket scopes before proper server-side authorization, enabling the execution of admin-gated Gateway RPCs until the connection is closed or revalidated.
date: "2026-07-03T12:03:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
  - websocket
  - npm
vendors:
  - OpenClaw
products:
  - OpenClaw (< 2026.5.18)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An unpaired or restricted trusted-proxy Control UI client could obtain cached `operator.admin` authority on its live WebSocket connection. That authority could then be used for admin-gated Gateway RPCs until the connection was closed or revalidated.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qjpc-qf9m-xwmr
---

A significant vulnerability has been identified in OpenClaw's trusted-proxy Control UI, designated GHSA-qjpc-qf9m-xwmr. This flaw permits an attacker to bypass authorization mechanisms by declaring elevated operator scopes via a WebSocket connection, even if their device identity is unpaired or restricted. Specifically, the system accepts these client-declared scopes before validating them against a server-approved pairing or trusted-proxy authorization baseline. This can lead to a temporary privilege escalation, granting `operator.admin` authority which allows the execution of administrative Gateway RPCs. The issue affects OpenClaw deployments configured with `gateway.auth.mode: "trusted-proxy"` and impacts versions prior to `2026.5.18`. Defenders must prioritize upgrading to the patched version to prevent unauthorized access and potential system compromise.

## Attack Chain

1.  An attacker gains or establishes a connection to a trusted-proxy Control UI client with either an unpaired device identity or a restricted trusted-proxy user account.
2.  The attacker opens a WebSocket connection to the OpenClaw gateway using this client.
3.  During the WebSocket handshake or early communication, the attacker's client declares elevated operator scopes, such as `operator.admin`, for its session.
4.  The OpenClaw gateway, due to the vulnerability, accepts these client-declared scopes without immediately verifying them against the pre-established trusted-proxy authorization policy or a server-approved pairing.
5.  The attacker temporarily obtains cached `operator.admin` authority on their live WebSocket connection, despite their actual authorization level.
6.  Using this elevated authority, the attacker executes admin-gated Gateway RPCs, potentially performing unauthorized administrative actions.
7.  The administrative authority persists until the WebSocket connection is closed or the gateway performs a revalidation of the client's scopes.

## Impact

This vulnerability can lead to unauthorized administrative control over the OpenClaw gateway. An attacker exploiting this flaw could execute any `operator.admin`-gated RPCs, potentially leading to configuration changes, data manipulation, or denial of service within the affected system. While the authority is temporary (lasting until the connection closes or revalidates), it provides a window for attackers to cause significant damage. The vulnerability specifically targets deployments utilizing `gateway.auth.mode: "trusted-proxy"`, making environments relying on this mode susceptible to privilege escalation.

## Recommendation

*   Upgrade all OpenClaw installations to version `openclaw@2026.5.18` or later to patch the vulnerability as stated in the source.
*   Before upgrading, restrict trusted-proxy Control UI access to only those users who are genuinely authorized for the scopes they are permitted to request.
*   Restart the OpenClaw gateway after implementing any changes to the trusted-proxy authorization policy to ensure the new policies are active.
