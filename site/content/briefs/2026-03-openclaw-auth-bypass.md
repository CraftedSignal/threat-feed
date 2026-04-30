---
title: OpenClaw Feishu Webhook Authentication Bypass (CVE-2026-32974)
slug: 2026-03-openclaw-auth-bypass
description: OpenClaw before 2026.3.12 is vulnerable to an authentication bypass in Feishu webhook mode when only verificationToken is configured without encryptKey, allowing unauthenticated network attackers to inject forged Feishu events and trigger downstream tool execution.
date: "2026-03-29T13:17:01Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - authentication-bypass
  - webhook
  - cve-2026-32974
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32974
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-g353-mgv3-8pcj
  - https://www.vulncheck.com/advisories/openclaw-forged-event-injection-via-feishu-webhook-verification-token
rules:
  - title: Detect Forged Feishu Webhook Events
    description: Detects suspicious POST requests to the Feishu webhook endpoint indicative of CVE-2026-32974 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Processes Spawned by OpenClaw
    description: Detects unusual child processes spawned by the OpenClaw process, potentially triggered by forged events.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw before version 2026.3.12 is susceptible to an authentication bypass vulnerability (CVE-2026-32974) affecting Feishu webhook integrations. This vulnerability arises when the `verificationToken` is configured without the `encryptKey`. This configuration flaw enables unauthenticated attackers to forge Feishu events and send them to the webhook endpoint. Successful exploitation allows attackers to trigger arbitrary downstream tool execution within the OpenClaw environment. This is a…
