---
title: Gitea Server-Side Request Forgery Vulnerabilities
slug: 2026-07-gitea-ssrf
description: Two Server-Side Request Forgery (SSRF) vulnerabilities in Gitea version 1.26.2 and earlier allow authenticated users to bypass IP filtering for webhooks and repository migrations by targeting CGNAT and IPv6 transition prefixes, and unauthenticated users to trigger arbitrary GET requests against internal hosts via the OpenID sign-in form, potentially leading to internal network discovery and data exposure.
date: "2026-07-21T21:17:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - gitea
  - web-vulnerability
  - internal-reconnaissance
vendors:
  - Gitea Ltd
products:
  - Gitea <= 1.26.2
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: When OpenID sign-in is enabled, anyone on the internet can drive Gitea into making arbitrary GET requests against internal IPs.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
    evidence: Any logged-in user can create a webhook pointing at an internal CGNAT host. The full HTTP response from that host (status, headers, body up to 1 MB) is stored in the webhook delivery log and rendered to the webhook owner on the hook detail page.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
    evidence: The full HTTP response from that host (status, headers, body up to 1 MB) is stored in the webhook delivery log and rendered to the webhook owner on the hook detail page.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2fcr-jfvc-vgg2
iocs:
  - type: hash_sha256
    value: 7d13848af12645600a5f9d93ee2560daa9c6fa6b5b859b7bff3a5e1c0b661031
ioc_counts:
  hash_sha256: 1
rules:
  - title: Detect Gitea OpenID SSRF Attempt
    description: Detects attempts to exploit the OpenID SSRF vulnerability in Gitea by targeting internal IP addresses via the '/user/login/openid' endpoint.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - lateral_movement
    techniques:
      - T1018
      - T1595.002
    data_sources:
      - webserver
rules_count: 1
---

Two distinct Server-Side Request Forgery (SSRF) vulnerabilities have been identified in Gitea, affecting versions up to and including 1.26.2. The first finding concerns the `hostmatcher` IP classification logic used for outbound HTTP requests initiated by webhooks and repository migrations. This filter, intended to prevent internal network access, incorrectly allows connections to CGNAT (100.64.0.0/10) and several IPv6 transition prefixes, including NAT64, 6to4, and Teredo. An authenticated user can exploit this by crafting a webhook or migration URL to an internal CGNAT IP, causing Gitea to fetch the resource and store the response (up to 1MB) for retrieval. The second finding relates to the OpenID sign-in form, which, when enabled, allows unauthenticated users to provide a malicious OpenID provider URL. Gitea then fetches this URL server-side using `http.DefaultClient` without any IP filtering, enabling arbitrary GET requests against internal network resources. Both vulnerabilities can lead to significant internal network reconnaissance and potential data exfiltration from the Gitea host.

## Attack Chain

### Scenario 1: Authenticated Webhook/Migration SSRF

1. Attacker establishes authenticated access to a Gitea instance, either as a regular user or a repository administrator.
2. Attacker navigates to the webhook creation interface or initiates a repository migration.
3. Attacker crafts a malicious URL for the webhook or migration target, specifying an internal host within a CGNAT IP range (e.g., `http://100.64.0.2:8080/internal`) or an unblocked IPv6 transition prefix.
4. The crafted URL is submitted via Gitea's API for webhook or migration configuration.
5. Gitea's `hostmatcher` IP filter, due to a flaw in its `IsGlobalUnicast() && !IsPrivate()` logic, fails to block the CGNAT or IPv6 transition range IP.
6. Gitea initiates an outbound HTTP request to the specified internal CGNAT host.
7. The target internal host's HTTP response, including status, headers, and body (up to 1 MB), is captured by Gitea.
8. Attacker retrieves the stored response from the webhook delivery logs or migration details, gaining insights into internal network services or sensitive data.

### Scenario 2: Unauthenticated OpenID SSRF

1. The Gitea instance has OpenID sign-in enabled, which is the default setting prior to initial installation completion (`!InstallLock`) or explicitly configured afterwards.
2. An unauthenticated attacker sends a specially crafted HTTP POST request to Gitea's `/user/login/openid` endpoint.
3. The POST request includes an `openid` parameter with a URL pointing to an internal IP address (e.g., `http://192.168.1.100/admin`) within the Gitea's network.
4. Gitea's `openid-go` library, responsible for OpenID discovery, uses `http.DefaultClient` without any IP filtering or `hostmatcher` integration.
5. Gitea initiates an outbound HTTP GET request to the internal IP address specified in the `openid` parameter.
6. The internal service receives the GET request from Gitea, potentially triggering actions, revealing its presence, or exposing information, even if the response is not directly returned to the attacker.

## Impact

Successful exploitation of these SSRF vulnerabilities can lead to significant internal network reconnaissance, allowing attackers to discover active hosts, open ports, and running services within the Gitea environment. For the webhook and migration SSRF, sensitive information (up to 1MB of HTTP response data) from internal services can be exfiltrated and viewed by the attacker, potentially revealing API keys, configuration details, or other confidential data. While the OpenID SSRF does not directly exfiltrate data to the attacker, it enables unauthenticated port scanning and interaction with internal services, which can be a precursor to more sophisticated attacks, including lateral movement or exploitation of other internal vulnerabilities. Organizations using Gitea versions 1.26.2 or older are at risk, particularly those with OpenID sign-in enabled or those that allow user-created webhooks and repository migrations.

## Recommendation

* Deploy the provided Sigma rule to detect attempts at exploiting the OpenID SSRF vulnerability via webserver logs.
* Patch Gitea instances to the latest available version immediately, as fixes for these SSRF vulnerabilities are expected in subsequent releases.
* Restrict outbound network access from Gitea servers to only necessary external endpoints using firewall rules to mitigate the impact of SSRF, even if internal IP filtering is bypassed.
* If OpenID sign-in is not strictly required, disable it in Gitea's configuration to eliminate the unauthenticated SSRF vector.
* Monitor Gitea's outgoing network connections for attempts to contact internal IP addresses, especially those in CGNAT ranges (e.g., 100.64.0.0/10) or RFC 1918 ranges, which would indicate successful exploitation of the webhook/migration SSRF.
