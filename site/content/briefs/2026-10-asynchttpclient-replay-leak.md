---
title: AsyncHttpClient Credential and Request Leakage via Host Replay
slug: 2026-10-asynchttpclient-replay-leak
description: A vulnerability in AsyncHttpClient causes sensitive credentials and request details to be leaked to unintended hosts when a request replay or failover is triggered.
date: "2026-10-08T19:25:36Z"
lastmod: "2026-10-08T19:27:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:asynchttpclient:async_http_client:*:*:*:*:*:*:*:*
tags:
  - credential-theft
  - data-leakage
  - library-vulnerability
  - authentication-bypass
  - cve-2026-107230
  - java
vendors:
  - AsyncHttpClient
products:
  - async-http-client (<= 2.16.0)
  - async-http-client (<= 3.0.12)
  - async-http-client (< 3.0.14)
  - async-http-client (<= 2.16.1)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage Object
    evidence: The client updates only the current request and leaves the target request pointing at the original host, each one sends the first host's request, credentials, or both to the second host.
    confidence_band: high
cves:
  - id: CVE-2026-107282
references:
  - https://github.com/advisories/GHSA-jmqq-x5g9-9p2w
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107282
  - https://github.com/advisories/GHSA-v2j5-22fr-j62r
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107230
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade all instances of async-http-client to version 3.0.13 or 2.16.1.
      owner: Development
      due: 24h
      evidence: Patches for CVE-2026-107282 are released in these versions.
  mitigation_plan:
    - priority: immediate
      action: Disable ResponseFilter failover to different hosts and disable automatic request retries.
      owner: Development
      addresses: CVE-2026-107282
      evidence: Source workaround provided for instances where patching is delayed.
updates:
  - at: "2026-10-08T19:27:09Z"
    level: L2
    summary: added coverage for async-http-client (< 3.0.14) +1 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-v2j5-22fr-j62r
---

AsyncHttpClient (v2.x <= 2.16.0 and v3.x <= 3.0.12) contains a critical vulnerability, CVE-2026-107282, that leads to the leakage of credentials and sensitive request data. The issue stems from the library's handling of request replays and failover patterns - triggered by `ResponseFilter` or automatic `IOException` retries. When a request is replayed to a different host, the internal `targetRequest` pointer is not updated to match the new host, leaving it pointing to the original destination. 

As a result, subsequent connection pool operations, tunneling requests, and realm-based authentication processes use stale request data. This leads to the application sending sensitive headers, such as `Authorization`, to the wrong host. Furthermore, if the protocol upgrades from HTTP to HTTPS during the replay, the client may fail to install an SSL handler, causing the transmission of credentials in cleartext. Defenders should note that this behavior occurs via documented features, making it a design-level defect rather than a recent regression.

## Attack Chain

1. An application configured with AsyncHttpClient attempts to perform a failover or retry operation upon encountering an error.
2. The `ResponseFilter` or `IOException` retry path triggers a request replay to a new destination host (Host B).
3. The `NettyRequestSender` component initiates the request but fails to update the target request object, retaining the original destination (Host A) headers and metadata.
4. The client's connection pool incorrectly keys the connection to Host B under the identity of Host A.
5. Subsequent authentication routines read the stale target request, attaching Host A's `Authorization` header to the traffic destined for Host B.
6. The `NettyConnectListener` logic fails to install an SSL handler if the original request was HTTP and the replay is HTTPS, bypassing intended security controls.
7. The replayed request - containing sensitive data - is transmitted to Host B, resulting in unauthorized credential exposure.

## Impact

The vulnerability results in the unauthorized exposure of authentication credentials and potentially sensitive request content to third-party or unauthorized hosts. This impact is significant for applications that utilize connection pooling, automated failover, or retry mechanisms in environments requiring strict confidentiality. Any service integrated with this library in these versions is susceptible to credential harvesting if an adversary controls or can intercept the replayed destination.

## Recommendation

* Upgrade to version 3.0.13 or 2.16.1 of `async-http-client` immediately to patch the target request management logic.
* If upgrading is not immediately possible, disable `ResponseFilter` logic that redirects requests to different hosts.
* Disable automatic request retries for applications configured with credentials or that operate via proxies to mitigate the risk of accidental credential leakage during failover scenarios.
