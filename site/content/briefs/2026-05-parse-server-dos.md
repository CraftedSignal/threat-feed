---
title: Parse Server Pre-authentication Denial of Service via Client Version Header
slug: 2026-05-parse-server-dos
description: A denial-of-service vulnerability, CVE-2026-47138, exists in Parse Server due to inefficient regular expression handling of the client SDK version field in HTTP requests, allowing an unauthenticated attacker to exhaust server resources by sending a crafted request with a malicious `X-Parse-Client-Version` header or `_ClientVersion` body field.
date: "2026-05-23T00:14:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - regex-backtracking
  - CVE-2026-47138
vendors:
  - npm
products:
  - parse-server
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-38m6-82c8-4xfm
  - CVE-2026-47138
rules:
  - title: Detect Malicious Parse Client Version Header
    description: Detects CVE-2026-47138 exploitation — identifies HTTP requests to Parse Server with a suspicious X-Parse-Client-Version header indicative of a denial-of-service attack attempt.
    platform: sigma
    severity: high
    tactics:
      - dos
    techniques:
      - T1499.001
    data_sources:
      - webserver
  - title: Detect Malicious Parse Client Version Body Field
    description: Detects CVE-2026-47138 exploitation — identifies HTTP requests to Parse Server with a suspicious _ClientVersion field in JSON body indicative of a denial-of-service attack attempt.
    platform: sigma
    severity: high
    tactics:
      - dos
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 2
---

Parse Server is susceptible to a denial-of-service (DoS) attack due to inefficient regular expression parsing of the client SDK version. The vulnerability, identified as CVE-2026-47138, affects Parse Server versions prior to 8.6.77 and versions 9.0.0 to 9.9.1-alpha.1. An unauthenticated attacker can exploit this by sending a specially crafted HTTP request to the `/parse/*` endpoint. This request contains a malicious client SDK version in either the `X-Parse-Client-Version` header or the `_ClientVersion` field within the JSON request body. The vulnerability stems from polynomial backtracking in the regex parser, causing excessive CPU consumption. A small number of concurrent requests can saturate a worker, leading to a denial-of-service condition. This issue is pre-authentication, meaning an attacker does not need valid credentials to trigger it.

## Attack Chain

1. An attacker identifies a publicly accessible Parse Server instance.
2. The attacker crafts an HTTP request targeting the `/parse/*` endpoint.
3. The attacker includes a malicious string in the `X-Parse-Client-Version` header of the request, designed to trigger polynomial backtracking in the server's regex parser. Alternatively, the `_ClientVersion` field can be included in the JSON body.
4. The Parse Server receives the request and attempts to parse the `X-Parse-Client-Version` header (or `_ClientVersion` body field) using a vulnerable regular expression.
5. The crafted malicious input causes the regex parser to enter a computationally expensive backtracking loop.
6. This loop consumes significant CPU resources on the server's Node.js worker.
7. Multiple concurrent requests from the attacker exhaust the CPU resources of the available workers.
8. Legitimate requests to the Parse Server are delayed or dropped, resulting in a denial-of-service condition for legitimate users.

## Impact

Successful exploitation of CVE-2026-47138 can lead to a denial-of-service condition, rendering the Parse Server unavailable to legitimate users. This can disrupt applications relying on the server and negatively impact business operations. The vulnerability is easily exploitable by unauthenticated attackers who know a publicly known Parse Application ID, making it a significant threat to production deployments running the default configuration.

## Recommendation

*   Upgrade Parse Server to version 8.6.77 or later, or version 9.9.1-alpha.1 or later to remediate CVE-2026-47138.
*   Deploy a reverse proxy or Web Application Firewall (WAF) to strip the `X-Parse-Client-Version` header AND the `_ClientVersion` field in JSON request bodies on every `/parse/*` route before forwarding to the server, as mentioned in the workaround.
*   Implement strict size limits on request headers and bodies via the reverse proxy or WAF, even after patching.
*   Deploy the Sigma rule `Detect Malicious Parse Client Version Header` to identify exploitation attempts.
