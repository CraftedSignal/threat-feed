---
title: prompts.chat Fal.ai SSRF Vulnerability (CVE-2026-22664)
slug: 2026-04-prompts-chat-ssrf
description: prompts.chat prior to commit 30a8f04 is vulnerable to server-side request forgery (SSRF) in Fal.ai media status polling, allowing authenticated users to perform arbitrary outbound requests by supplying attacker-controlled URLs, leading to potential credential theft and internal network probing.
date: "2026-04-03T21:17:09Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - ssrf
  - cve-2026-22664
  - fal.ai
  - prompts.chat
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-22664
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22664
  - https://gist.github.com/mdisec/27c0cac0ec6a8f3c8f85a18987ddb942
  - https://github.com/f/prompts.chat/commit/30a8f0470e0ba45e6be9c9f55220f4a9a6b91c99
  - https://www.vulncheck.com/advisories/prompts-chat-ssrf-via-fal-ai-media-status-polling
iocs:
  - type: url
    value: https://www.vulncheck.com/advisories/prompts-chat-ssrf-via-fal-ai-media-status-polling
  - type: url
    value: https://gist.github.com/mdisec/27c0cac0ec6a8f3c8f85a18987ddb942
  - type: url
    value: https://github.com/f/prompts.chat/commit/30a8f0470e0ba45e6be9c9f55220f4a9a6b91c99
ioc_counts:
  url: 3
rules:
  - title: Detect prompts.chat SSRF via Suspicious Token Parameter
    description: Detects potential SSRF attempts in prompts.chat by identifying HTTP requests with a token parameter containing a suspicious URL.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect prompts.chat Outbound Connection to Uncommon Destination
    description: Detects prompts.chat server making outbound connection to uncommon destination, which may indicate SSRF.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

prompts.chat, a web application, contains a server-side request forgery (SSRF) vulnerability affecting versions prior to commit 30a8f04. This flaw resides in the Fal.ai media status polling feature. An authenticated user can inject arbitrary URLs into the `token` parameter, causing the server to make outbound requests to attacker-controlled destinations. The vulnerability, identified as CVE-2026-22664, allows attackers to potentially extract the `FAL_API_KEY` from the `Authorization` header during these requests. Successful exploitation can result in credential theft, internal network probing, and abuse of the victim's Fal.ai account. This vulnerability poses a significant risk as it could lead to unauthorized access and data breaches.

## Attack Chain

1.  Attacker authenticates to the prompts.chat application.
2.  Attacker crafts a malicious URL containing a server controlled by them.
3.  The attacker initiates a media status polling request to Fal.ai, injecting the malicious URL into the `token` parameter.
4.  The prompts.chat server, lacking proper URL validation, makes an outbound HTTP request to the attacker's server.
5.  The request includes the `Authorization` header, potentially exposing the `FAL_API_KEY`.
6.  The attacker's server captures the `Authorization` header containing the `FAL_API_KEY`.
7.  The attacker uses the stolen `FAL_API_KEY` to access the victim's Fal.ai account.
8.  The attacker performs unauthorized actions, such as data exfiltration or resource abuse.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-22664) allows attackers to steal the `FAL_API_KEY`, potentially impacting all users of the vulnerable prompts.chat application who utilize the Fal.ai integration. Consequences include unauthorized access to Fal.ai accounts, data breaches, internal network scans originating from the prompts.chat server, and financial losses due to resource abuse. The specific number of victims and the extent of the damage depend on the attacker's objectives and the permissions associated with the compromised Fal.ai API key.

## Recommendation

*   Inspect web server logs for outbound requests to unusual or suspicious domains originating from the prompts.chat server to detect potential SSRF attempts (log source: webserver).
*   Deploy the provided Sigma rule to detect HTTP requests containing a suspicious `token` parameter potentially indicative of SSRF exploitation.
*   Monitor network traffic for unusual outbound connections from the prompts.chat server (log source: network_connection).
*   Apply the patch or upgrade prompts.chat to a version after commit 30a8f04, which addresses the CVE-2026-22664 vulnerability.
