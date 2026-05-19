---
title: zrok ProxyShare SSRF Vulnerability (CVE-2026-45568)
slug: 2026-05-zrok-ssrf
description: The zrok Python SDK `ProxyShare` is vulnerable to server-side request forgery (SSRF) via CVE-2026-45568. When a user sends a request with an absolute URL in the path, the Flask handler passes that path to `urllib.parse.urljoin`, which replaces the configured target host with the user-supplied host, causing the proxy to send the request to an attacker-chosen URL.
date: "2026-05-19T15:16:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - cve
  - cve-2026-45568
  - zrok
  - proxyshare
vendors:
  - pip
products:
  - zrok (>= 0.4.47, <= 1.1.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-jh67-hwqw-m5r7
  - CVE-2026-45568
rules:
  - title: Detect zrok SSRF Attempt via Absolute URL in Request Path
    description: Detects CVE-2026-45568 exploitation — an SSRF attempt against zrok ProxyShare by detecting HTTP requests containing an absolute URL in the path.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect zrok SSRF Attempt via URL-encoded Absolute URL in Request Path
    description: Detects CVE-2026-45568 exploitation — an SSRF attempt against zrok ProxyShare using a URL-encoded absolute URL in the path. This is a variation of the basic SSRF attack.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The zrok Python SDK, specifically the `ProxyShare` functionality, is susceptible to a server-side request forgery (SSRF) vulnerability, identified as CVE-2026-45568. This flaw exists due to the use of `urllib.parse.urljoin` without proper sanitization of the input path. An attacker can exploit this by crafting a request containing an absolute URL in the path. The Flask handler then passes this malicious path to `urljoin`, which incorrectly combines it with the target URL. This results in the proxy forwarding the request to an attacker-controlled server instead of the intended target, potentially leading to information disclosure or internal network access. The vulnerability affects zrok versions 0.4.47 through 1.1.11. This matters for defenders because it allows an attacker to bypass intended access controls and potentially gain access to internal resources.

## Attack Chain

1. Alice configures a zrok `ProxyShare` with a defined target URL, for example, `https://internal-api.example.com`.
2. Bob identifies the exposed `ProxyShare` endpoint.
3. Bob crafts a malicious request to the `ProxyShare` endpoint, including an absolute URL in the path, such as `/http://127.0.0.1:19190/metadata`.
4. The Flask application routes the request to the `proxy` function.
5. The `proxy` function uses `urllib.parse.urljoin(self.target, path)` to construct the outbound URL. Due to the absolute URL in `path`, `urljoin` resolves to `http://127.0.0.1:19190/metadata` instead of a URL on Alice's intended target.
6. The `requests.request` function sends the crafted request to the attacker-controlled URL (`http://127.0.0.1:19190/metadata`).
7. The attacker's server (`127.0.0.1:19190`) receives the request, potentially including sensitive information or internal headers.
8. The attacker's server responds, and the response is relayed back to Bob, completing the SSRF attack.

## Impact

Successful exploitation of CVE-2026-45568 allows an attacker to perform SSRF attacks against zrok deployments. This can enable the attacker to access internal services, read sensitive data from internal endpoints, or potentially perform actions on behalf of the zrok server. The impact can range from information disclosure to full compromise of internal systems, depending on the services accessible from the zrok server.

## Recommendation

*   Upgrade zrok to a version beyond 1.1.11 to patch CVE-2026-45568.
*   Deploy the Sigma rule "Detect zrok SSRF Attempt via Absolute URL in Request Path" to detect exploitation attempts against vulnerable zrok instances.
*   Monitor web server logs for requests containing absolute URLs in the path to the zrok proxy endpoint to identify potential SSRF attempts, referencing the attack chain described above.
