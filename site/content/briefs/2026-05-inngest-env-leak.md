---
title: Inngest SDK Exposes Environment Variables via Unhandled HTTP Methods
slug: 2026-05-inngest-env-leak
description: Inngest TypeScript SDK versions 3.22.0 through 3.53.1 expose environment variables via the serve() handler on unhandled HTTP methods, allowing unauthenticated remote attackers to exfiltrate environment variables from the host process via `PATCH`, `OPTIONS`, or `DELETE` requests to the `serve()` HTTP handler.
date: "2026-05-05T18:13:52Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - environment-variable-exposure
  - inngest
  - cve-2026-42047
vendors:
  - Inngest
  - Vercel
  - Cloudflare
products:
  - inngest TypeScript SDK
  - Vercel
  - Cloudflare Workers
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-2jf5-6wwv-vhxx
  - https://www.inngest.com/docs/learn/serving-inngest-functions
  - https://vercel.com/docs/deployment-protection#standard-protection
  - https://vercel.com/kb/guide/how-do-i-delete-an-individual-deployment
  - https://www.inngest.com/docs/platform/manage/rotating-keys
  - https://www.inngest.com/docs/platform/signing-keys
  - https://www.inngest.com/docs/events/creating-an-event-key
  - https://www.inngest.com/docs/learn/security
iocs:
  - type: url
    value: http://inngest.com/ips-v4
  - type: url
    value: http://inngest.com/ips-v6
ioc_counts:
  url: 2
rules:
  - title: Detect Inngest Serve Endpoint Access with Non-Standard HTTP Methods
    description: Detects requests to the Inngest serve endpoint using HTTP methods other than GET, POST, or PUT, which could indicate an attempt to exploit the environment variable exposure vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume of HTTP OPTIONS Requests
    description: Detects a high volume of HTTP OPTIONS requests which can be used for reconnaissance purposes. This can indicate an attempt to enumerate available resources and potentially identify vulnerable endpoints such as the Inngest serve endpoint.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability exists in the Inngest TypeScript SDK versions 3.22.0 through 3.53.1. This flaw allows unauthenticated remote attackers to extract environment variables from the host process by sending `PATCH`, `OPTIONS`, or `DELETE` requests to the `serve()` HTTP handler. The vulnerability arises because these HTTP methods are not explicitly handled and fall through to a diagnostic handler that inadvertently exposes the contents of `process.env`. This exposure includes sensitive information such as secrets, API keys, and credentials. Applications are vulnerable if they use the affected SDK versions and their `serve()` endpoint is reachable via the aforementioned HTTP methods. The vulnerability was introduced in version 3.22.0 and fixed in 3.54.0. There are no known reports of active exploitation at this time.

## Attack Chain

1.  The attacker identifies an Inngest application using a vulnerable SDK version (3.22.0 - 3.53.1).
2.  The attacker determines the application's `serve()` endpoint URL.
3.  The attacker sends an HTTP request to the `serve()` endpoint using the `PATCH`, `OPTIONS`, or `DELETE` method.
4.  The Inngest SDK's `serve()` handler, lacking specific handling for these methods, falls through to a generic diagnostic handler.
5.  The diagnostic handler inadvertently includes the contents of `process.env` in its response.
6.  The attacker receives the HTTP response containing the application's environment variables.
7.  The attacker extracts sensitive information from the environment variables, such as API keys or credentials.
8.  The attacker uses the extracted credentials to gain unauthorized access to resources or perform malicious actions.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to access sensitive environment variables. This can lead to the exposure of API keys, database credentials, and other secrets, potentially leading to unauthorized access to internal systems, data breaches, or other malicious activities. The number of affected applications depends on the adoption rate of the vulnerable Inngest SDK versions. Sectors utilizing Inngest for background job processing or event-driven architectures are particularly at risk.

## Recommendation

*   Upgrade to `inngest@3.54.0` or later to patch the vulnerability as mentioned in the overview.
*   Rotate any secrets that were present in environment variables (`process.env`) within affected environments, including Inngest signing keys and event keys, as described in the remediation steps in the advisory.
*   Search logs for any requests to your `serve` endpoints using the `PATCH`, `OPTIONS`, `DELETE` HTTP methods to assess if any environment variables may have been exposed, as described in the remediation steps in the advisory.
*   Adjust firewall or proxy rules to only allow requests to your `serve` endpoint from Inngest IP addresses available at http://inngest.com/ips-v4 and http://inngest.com/ips-v6.
