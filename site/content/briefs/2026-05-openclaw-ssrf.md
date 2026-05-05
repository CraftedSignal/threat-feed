---
title: OpenClaw QQBot Reply Media URL SSRF Vulnerability
slug: 2026-05-openclaw-ssrf
description: OpenClaw before version 2026.4.12 is vulnerable to server-side request forgery (SSRF) in QQBot reply media URL handling, allowing attackers to fetch arbitrary content by providing malicious media URLs.
date: "2026-05-05T12:16:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw
  - QQBot reply media URL handling
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-43526
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43526
  - https://github.com/openclaw/openclaw/commit/08ae021d1f4f02e0ca5fd8a3b9659291c1ecf95a
  - https://github.com/openclaw/openclaw/commit/ddb7a8dd80b8d5dd04aafa44ce7a4354b568bb2d
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-2767-2q9v-9326
  - https://www.vulncheck.com/advisories/openclaw-server-side-request-forgery-via-qqbot-reply-media-url-handling
rules:
  - title: Detect Outbound Connections to Internal IP Ranges from OpenClaw
    description: Detects outbound network connections from OpenClaw server to private IP address ranges, which could indicate SSRF attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect OpenClaw accessing the local host
    description: Detects outbound network connections from OpenClaw server to the local host, which could indicate SSRF attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

OpenClaw before version 2026.4.12 is susceptible to a server-side request forgery (SSRF) vulnerability within its QQBot reply media URL handling. This flaw allows an attacker to force the application to make requests to arbitrary internal or external resources. By providing crafted, malicious media URLs, an attacker can trigger SSRF requests. The bytes fetched from these requests are subsequently re-uploaded through the communication channel. This vulnerability allows attackers to potentially access sensitive internal resources, bypass firewalls, or perform other malicious actions.

## Attack Chain

1. An attacker crafts a malicious media URL containing a target internal resource (e.g., `http://internal-server/sensitive-data`).
2. The attacker sends a message to QQBot with the crafted malicious media URL as part of a reply.
3. QQBot processes the message and attempts to fetch the media from the specified URL.
4. Due to the SSRF vulnerability, QQBot makes an HTTP request to the attacker-controlled URL (e.g., `http://internal-server/sensitive-data`).
5. The internal server responds to the request, sending back the requested data to QQBot.
6. QQBot receives the response and re-uploads the fetched data through the channel.
7. The attacker gains access to the content of the internal resource that was fetched by QQBot.

## Impact

Successful exploitation of this SSRF vulnerability allows attackers to read internal files, access sensitive data, and potentially pivot to other internal systems. The impact is significant due to the potential for unauthorized access to sensitive resources that should not be publicly accessible. Number of victims and targeted sectors are currently unknown.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.12 or later to patch CVE-2026-43526.
*   Monitor network connections originating from the OpenClaw server for suspicious outbound requests to internal resources.
