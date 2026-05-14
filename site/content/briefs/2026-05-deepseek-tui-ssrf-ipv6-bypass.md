---
title: DeepSeek TUI SSRF Vulnerability via IPv6 Bypass (CVE-2026-45373)
slug: 2026-05-deepseek-tui-ssrf-ipv6-bypass
description: DeepSeek TUI is vulnerable to Server-Side Request Forgery (SSRF) due to insufficient validation against IPv6 addresses. When providing an IPv6 address in a URL as `http://[::1]`, the SSRF defenses are bypassed, potentially allowing access to local restricted resources, tracked as CVE-2026-45373.
date: "2026-05-14T20:36:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-45373
  - deepseek-tui
products:
  - deepseek-tui (< 0.8.26)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-88gh-2526-gfrr
  - https://github.com/Hmbown/DeepSeek-TUI/blob/15f62e3e93d842f30b428877819ebc1c8cb96814/crates/tui/src/tools/fetch_url.rs#L321
rules:
  - title: Detect DeepSeek TUI SSRF Attempt via IPv6 Bypass
    description: Detects CVE-2026-45373 exploitation — attempts to exploit the SSRF vulnerability in DeepSeek TUI by using a URL containing the IPv6 localhost address `http://[::1]`.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

DeepSeek TUI versions prior to 0.8.26 are susceptible to a Server-Side Request Forgery (SSRF) vulnerability. The application's input validation fails to properly sanitize IPv6 addresses provided in URLs, specifically when formatted as `http://[::1]`. This bypass allows an attacker to potentially circumvent intended access controls and interact with internal or restricted resources that would otherwise be inaccessible from the outside network. This vulnerability allows attackers to potentially read sensitive data or execute commands within the internal network.

## Attack Chain

1. Attacker crafts a malicious URL containing an IPv6 address in the format `http://[::1]`.
2. The attacker inputs this URL into the DeepSeek TUI, specifically targeting the `fetch_url` tool.
3. The `fetch_url` tool in `src/tools/fetch_url.rs` attempts to process the provided URL.
4. The application's SSRF defenses fail to properly validate the IPv6 address `[::1]`.
5. The application initiates a request to the specified IPv6 address (localhost).
6. The request is routed to a local service or resource on the server.
7. The attacker gains access to the content or functionality of the local resource.
8. The attacker can potentially read sensitive information or perform actions within the internal network.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-45373) can lead to unauthorized access to internal resources and sensitive information. Attackers could potentially read configuration files, access internal APIs, or even execute arbitrary commands on the server, depending on the accessible local resources. The specific impact depends on the configuration and services running on the targeted host.

## Recommendation

- Upgrade DeepSeek TUI to version 0.8.26 or later to remediate CVE-2026-45373.
- Deploy the Sigma rule `Detect DeepSeek TUI SSRF Attempt via IPv6 Bypass` to detect exploitation attempts.
