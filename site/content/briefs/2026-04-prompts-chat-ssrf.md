---
title: prompts.chat Fal.ai SSRF Vulnerability (CVE-2026-22664)
slug: 2026-04-prompts-chat-ssrf
description: prompts.chat prior to commit 30a8f04 is vulnerable to server-side request forgery (SSRF) in Fal.ai media status polling, allowing authenticated users to perform arbitrary outbound requests by supplying attacker-controlled URLs, leading to potential credential theft and internal network probing.
date: "2026-04-03T21:17:09Z"
severities:
  - high
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

prompts.chat, a web application, contains a server-side request forgery (SSRF) vulnerability affecting versions prior to commit 30a8f04. This flaw resides in the Fal.ai media status polling feature. An authenticated user can inject arbitrary URLs into the `token` parameter, causing the server to make outbound requests to attacker-controlled destinations. The vulnerability, identified as CVE-2026-22664, allows attackers to potentially extract the `FAL_API_KEY` from the `Authorization` header…
