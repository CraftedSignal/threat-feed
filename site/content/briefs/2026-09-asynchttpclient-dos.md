---
title: AsyncHttpClient Unbounded Decompression Denial of Service
slug: 2026-09-asynchttpclient-dos
description: AsyncHttpClient is vulnerable to a decompression bomb denial of service attack due to unbounded automatic HTTP/1.1 response decompression, potentially leading to heap exhaustion.
date: "2026-09-17T19:10:46Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:asynchttpclient:async_http_client:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - java
vendors:
  - AsyncHttpClient
products:
  - async-http-client (<= 2.16.0)
  - async-http-client (3.0.0 - 3.0.11)
cves:
  - id: CVE-2026-85721
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-7grg-jcf7-rpmx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85721
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Audit build environments for vulnerable async-http-client versions
      owner: Application Security
      due: 24h
      evidence: CVE-2026-85721 advisory details
  mitigation_plan:
    - priority: immediate
      action: Upgrade async-http-client to version 3.0.13 or higher
      owner: IT Operations
      addresses: CVE-2026-85721
      evidence: Source explicitly mandates upgrade to 3.0.13 to address regression
---

AsyncHttpClient (CVE-2026-85721) is susceptible to a denial of service (DoS) vulnerability caused by the lack of size constraints during automatic HTTP response decompression. By default, the client library decompresses response bodies using algorithms such as gzip, deflate, and snappy. Because the library fails to limit the total accumulated output size, a malicious or compromised server can deliver a specially crafted, small compressed payload that expands exponentially upon processing. This results in rapid memory consumption, exhausting the client's heap and triggering an OutOfMemoryError. 

This issue affects AsyncHttpClient 3.x up to and including 3.0.11 and 2.x up to and including 2.16.0. While 3.0.11 introduced a limit for the HTTP/2 path, versions 3.0.8 through 3.0.10 remain vulnerable to HTTP/2-based decompression bombs as well. Organizations are advised to upgrade to 3.0.13, as version 3.0.12 introduced a secondary security regression (GHSA-rqf5-2wxv-rjf4) involving potential cleartext credential transmission during authentication downgrades.

## Impact

Successful exploitation results in application-level denial of service via memory exhaustion, potentially impacting any service relying on AsyncHttpClient to fetch content from third-party or untrusted servers. The vulnerability is highly relevant for middleware, API gateways, and web crawlers that frequently handle large numbers of external HTTP responses. Given the nature of decompression bombs, the attack requires minimal bandwidth, allowing a single malicious endpoint to disable multiple client instances simultaneously.

## Recommendation

* Upgrade async-http-client dependencies to version 3.0.13 or later to mitigate both the decompression bomb vulnerability and the associated authentication credential exposure issue.
* For legacy 2.x implementations that cannot be upgraded, remove the inflater handler through the httpAdditionalChannelInitializer configuration to prevent automatic decompression.
* Implement egress proxy controls that inspect and cap the size of uncompressed response bodies before they are passed to the AsyncHttpClient library.
* Review application logs for OutOfMemoryError exceptions occurring during outbound HTTP requests to identify potential active exploitation attempts.
