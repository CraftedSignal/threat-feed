---
title: 'OpenClaw Trust Model Vulnerability: System Prompt Channel Injection'
slug: 2026-04-openclaw-trust-model
description: OpenClaw versions 2026.4.2 and earlier are vulnerable to a trust model issue where authenticated wake hooks or mapped wake payloads can be promoted into the trusted System prompt channel, potentially leading to security vulnerabilities within the OpenClaw trust model.
date: "2026-04-09T14:22:23Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - openclaw
  - trust-model
  - system-prompt-injection
  - npm
references:
  - https://github.com/advisories/GHSA-jf56-mccx-5f3f
rules:
  - title: Detect Suspicious Process Execution After /hooks/wake Request
    description: Detects potential exploitation of the OpenClaw trust model vulnerability by monitoring for suspicious process execution shortly after a /hooks/wake request.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Access to /hooks/wake endpoint
    description: Detects access to the /hooks/wake endpoint, which may indicate an attempt to exploit the OpenClaw trust model vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, a user-controlled local assistant, is susceptible to a vulnerability affecting its trust model. This vulnerability, present in versions 2026.4.2 and earlier, allows authenticated `/hooks/wake` calls and mapped `wake` payloads to be improperly promoted into the trusted `System:` prompt channel. This occurs because the application fails to correctly differentiate between trusted system events and untrusted user-supplied events. The issue was reported on April 9th, 2026, and addressed in version 2026.4.8. The vulnerability specifically impacts the OpenClaw trust model, which assumes a single-tenant environment; it is not applicable to multi-tenant service boundaries. Defenders need to ensure OpenClaw is updated to the patched version to mitigate potential security exploits within this trust model.

## Attack Chain

1.  Attacker identifies a vulnerable OpenClaw instance running version 2026.4.2 or earlier.
2.  Attacker authenticates to the OpenClaw instance.
3.  Attacker crafts a malicious payload intended to be interpreted as a standard "wake" command.
4.  Attacker sends a specially crafted `/hooks/wake` request or a mapped `wake` payload containing the malicious content.
5.  Due to the vulnerability, OpenClaw incorrectly promotes the attacker-controlled payload into the trusted `System:` prompt channel.
6.  The OpenClaw assistant processes the malicious payload within the `System:` context, granting it elevated privileges within the application's trust model.
7.  The malicious payload executes arbitrary commands or actions within the OpenClaw environment as a trusted system component.
8.  The attacker achieves their objective, which could involve data manipulation, unauthorized access to local resources, or other malicious activities within the scope of the OpenClaw assistant.

## Impact

This vulnerability allows an attacker to inject malicious commands into the trusted system prompt channel of OpenClaw. Successful exploitation could lead to unauthorized data access, modification, or execution of arbitrary code within the OpenClaw environment. While the advisory does not specify the number of affected users, any instance running OpenClaw version 2026.4.2 or earlier is vulnerable. The primary risk is the compromise of the user's local assistant and potentially the data it manages.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.8 or later to remediate the vulnerability (reference: Affected Packages / Versions).
*   Monitor OpenClaw logs for suspicious activity related to the `/hooks/wake` endpoint (develop custom rules based on your OpenClaw logging configuration).
*   Deploy the Sigma rule provided in this brief to detect potential exploitation attempts by monitoring process execution following `/hooks/wake` requests.
