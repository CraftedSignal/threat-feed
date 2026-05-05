---
title: OpenClaw Privilege Escalation via Untrusted Webhook Wake Events (CVE-2026-43566)
slug: 2026-05-openclaw-privesc
description: OpenClaw versions 2026.4.7 before 2026.4.14 contain a privilege escalation vulnerability (CVE-2026-43566) where heartbeat owner downgrade logic skips webhook wake events carrying untrusted content, allowing attackers to preserve owner-like execution context.
date: "2026-05-05T12:16:20Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - privilege-escalation
  - webhook
  - cve-2026-43566
vendors:
  - OpenClaw
products:
  - OpenClaw
  - OpenClaw versions 2026.4.7 before 2026.4.14
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-43566
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43566
  - https://github.com/openclaw/openclaw/commit/31281bc92f55796817a92bc43f722cba1e77ab42
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-g2hm-779g-vm32
  - https://www.vulncheck.com/advisories/openclaw-privilege-escalation-via-untrusted-webhook-wake-events
rules:
  - title: Detect Suspicious Webhook Activity
    description: Detects potentially malicious webhook activity based on request characteristics. This rule looks for specific URI patterns and HTTP methods commonly associated with webhook interactions.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Webhook POST with Long URI
    description: Detects unusually long URI access using the POST method. This could be used to inject a payload via a webhook.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions 2026.4.7 through 2026.4.13 are vulnerable to a privilege escalation flaw, identified as CVE-2026-43566. This vulnerability stems from a failure in the heartbeat owner downgrade logic, which incorrectly skips webhook wake events that contain untrusted content. By exploiting this flaw, a malicious actor can craft and send untrusted webhook wake events, effectively maintaining an elevated, owner-like execution context even when the system should have downgraded privileges. This could allow unauthorized access and control within the OpenClaw environment.

## Attack Chain

1. An attacker identifies a vulnerable OpenClaw instance running versions 2026.4.7 - 2026.4.13.
2. The attacker crafts a malicious webhook wake event containing untrusted content.
3. The attacker sends the malicious webhook wake event to the targeted OpenClaw instance.
4. The OpenClaw instance receives the webhook wake event.
5. Due to the flawed heartbeat owner downgrade logic, the event is processed without proper privilege downgrading.
6. The attacker's process or script continues to execute with the privileges of the owner, rather than a more restricted user.
7. The attacker leverages the elevated privileges to access sensitive data or execute unauthorized commands.
8. The attacker maintains persistent access or further escalates privileges within the system.

## Impact

Successful exploitation of CVE-2026-43566 allows attackers to bypass intended security controls and gain unauthorized access to sensitive resources within the OpenClaw environment. This privilege escalation could lead to data breaches, system compromise, and other malicious activities. The number of affected installations is currently unknown, but any OpenClaw instance running a vulnerable version is at risk.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.14 or later to patch CVE-2026-43566.
*   Implement input validation and sanitization for all webhook wake events to prevent the injection of untrusted content.
*   Monitor OpenClaw logs for suspicious webhook activity and unexpected privilege escalations.
*   Deploy the Sigma rule "Detect Suspicious Webhook Activity" to identify potentially malicious webhook events.
*   Consider using a Web Application Firewall (WAF) to filter malicious requests, potentially blocking crafted webhook events before they reach the OpenClaw instance.
