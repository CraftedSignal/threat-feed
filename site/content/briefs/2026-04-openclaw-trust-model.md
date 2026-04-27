---
title: 'OpenClaw Trust Model Vulnerability: System Prompt Channel Injection'
slug: 2026-04-openclaw-trust-model
description: OpenClaw versions 2026.4.2 and earlier are vulnerable to a trust model issue where authenticated wake hooks or mapped wake payloads can be promoted into the trusted System prompt channel, potentially leading to security vulnerabilities within the OpenClaw trust model.
date: "2026-04-09T14:22:23Z"
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

OpenClaw, a user-controlled local assistant, is susceptible to a vulnerability affecting its trust model. This vulnerability, present in versions 2026.4.2 and earlier, allows authenticated `/hooks/wake` calls and mapped `wake` payloads to be improperly promoted into the trusted `System:` prompt channel. This occurs because the application fails to correctly differentiate between trusted system events and untrusted user-supplied events. The issue was reported on April 9th, 2026, and addressed in…
