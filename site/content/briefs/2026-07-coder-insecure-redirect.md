---
title: Coder Workspace Agent API Insecure Redirect Handling Allows Cross-Agent File Access and RCE
slug: 2026-07-coder-insecure-redirect
description: An authenticated user can exploit insecure redirect handling in the Coder workspace agent API to redirect API requests from their modified agent to a victim's online agent, enabling unauthorized file read/write operations and potential remote command execution across workspace and tenant boundaries.
date: "2026-07-06T21:57:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - file-manipulation
  - coder
  - server-side-request-forgery
  - ghsa
vendors:
  - Coder
products:
  - Coder < v2.34.4
  - Coder < v2.33.10
  - Coder < v2.32.9
  - Coder < v2.29.19
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: In affected versions that expose the workspace agent process API, the same primitive can be chained to command execution as the victim workspace user by writing a payload through the redirected file API and then redirecting a process-start request to execute it.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: If the attacker knows the victim agent UUID, they can derive the victim's tailnet IP and target the victim's file APIs to read or write files as the victim workspace user.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qrwj-vh9x-gw5v
  - https://github.com/coder/coder/pull/26600
---

A critical vulnerability (tracked as GHSA-qrwj-vh9x-gw5v) has been identified in Coder, a developer workspace platform, affecting its workspace agent API's redirect handling. Specifically, the `agentConn.apiClient()` utilized the default redirect behavior of `http.Client`, which could be abused by an authenticated user. By controlling a modified workspace agent, an attacker can craft HTTP redirects (e.g., 307 or 308) to point the control-plane client towards a victim agent's internal tailnet IP address. This bypasses security checks and causes subsequent API requests, intended for the attacker's agent, to be sent to the victim's agent instead. This can lead to unauthorized file reading and writing as the victim workspace user. In affected versions that expose the workspace agent process API, this primitive can be chained to achieve arbitrary command execution, effectively allowing attackers to cross workspace and tenant boundaries. The vulnerability affects Coder versions prior to v2.34.4, v2.33.10, v2.32.9, and v2.29.19 (ESR).

## Attack Chain

1.  An authenticated user gains control over and modifies a Coder workspace agent within their own workspace.
2.  The attacker, knowing the victim agent's UUID, deterministically calculates the victim agent's tailnet IP address.
3.  The attacker's modified agent returns an HTTP redirect (e.g., 307 or 308) in response to a control-plane client's API request.
4.  The crafted redirect's Location header specifies the derived tailnet IP of the victim agent.
5.  Due to insecure default redirect handling, the control-plane client follows the redirect, sending its subsequent workspace agent API request to the victim agent's IP instead of the intended (attacker's) agent.
6.  The victim agent, processing the request as if it originated legitimately from the control plane, performs the requested action (e.g., file read or write).
7.  If the workspace agent process API is exposed, the attacker writes a malicious payload via the redirected file API.
8.  The attacker then redirects a process-start request to execute the payload, achieving remote command execution as the victim workspace user and crossing workspace/tenant boundaries.

## Impact

Successful exploitation allows an authenticated user to gain unauthorized access to files and potentially achieve remote code execution (RCE) on other workspace agents within the Coder environment. This means an attacker can read sensitive files, modify critical data, or execute arbitrary commands as the victim workspace user, effectively compromising other users' workspaces and potentially breaching tenant boundaries. The consequence could range from data exfiltration and sabotage to complete compromise of sensitive development environments, leading to intellectual property theft or further network penetration. The vulnerability requires an authenticated user with control over a modified agent but the impact extends beyond their initial scope.

## Recommendation

*   Upgrade all Coder installations immediately to a patched version: v2.34.4, v2.33.10, v2.32.9, or v2.29.19 (ESR) or later, as specified in the provided patches section.
*   Ensure that Coder instances are updated to address GHSA-qrwj-vh9x-gw5v to disable automatic redirect following for workspace agent API clients.
*   Confirm that all workspace agent API dials pin to the intended agent's deterministic tailnet address and reject requests whose URL host does not match the intended agent, as described in the fix.
