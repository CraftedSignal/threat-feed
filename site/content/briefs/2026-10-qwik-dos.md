---
title: Unauthenticated Denial of Service in Qwik Framework
slug: 2026-10-qwik-dos
description: An unauthenticated remote denial-of-service vulnerability in Qwik allows attackers to terminate Node.js server processes by sending a maliciously crafted qwik-json payload, resulting in persistent service outages.
date: "2026-10-15T22:23:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:builder.io:qwik:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - webserver
  - application-vulnerability
vendors:
  - Builder.io
products:
  - Qwik (< 1.20.0)
  - Qwik Core (< 2.0.0-beta37)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A Qwik server in the default configuration can be crashed with one unauthenticated HTTP request.
    confidence_band: high
cves:
  - id: CVE-2026-84994
    epss: 0.00524
references:
  - https://github.com/advisories/GHSA-x586-xvc8-g7q6
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-84994
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade @builder.io/qwik to 1.20.0 or @qwik.dev/core to 2.0.0-beta37
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies version thresholds for remediation.
  mitigation_plan:
    - priority: immediate
      action: Implement strict rate limiting on all endpoints accepting POST requests
      owner: SOC
      addresses: CVE-2026-84994
      evidence: Attack is trivially repeatable per single request.
---

The Qwik framework is susceptible to a denial-of-service (DoS) vulnerability tracked as CVE-2026-84994, affecting versions of @builder.io/qwik prior to 1.20.0 and @qwik.dev/core prior to 2.0.0-beta37. The issue arises during the parsing of qwik-json bodies within the `ResourceSerializer.$fill$` function. When the framework processes a request containing a crafted object where the 'then' property is a QRL (Qwik URL) pointing to an unregistered symbol, the framework attempts to resolve the object as a promise. The resulting async rejection is not handled by the application, causing Node.js to trigger its default unhandled-rejection policy, which immediately terminates the process. Because the crash can be triggered by a single unauthenticated request, an attacker can maintain a persistent outage by continuously sending the exploit payload to any reachable Qwik-enabled endpoint.

## Attack Chain

1. Attacker identifies a web application utilizing a vulnerable version of the Qwik framework.
2. Attacker crafts an HTTP request with a malformed qwik-json body.
3. Attacker embeds a 'thenable' object within the JSON payload containing a QRL reference to an unregistered symbol.
4. The application server receives the POST request and initiates parsing of the qwik-json body.
5. The `ResourceSerializer.$fill$` logic attempts to resolve the provided 'thenable' object.
6. The underlying Node.js runtime fails to handle the asynchronous rejection triggered by the invalid QRL.
7. The Node.js process encounters an unhandled promise rejection and shuts down.
8. Service availability is lost for the affected server instance, leading to DoS.

## Impact

The attack results in the immediate termination of the server process, rendering the application unavailable. In environments without robust process management or rapid restarts, this vulnerability enables an attacker to achieve a permanent denial-of-service state for the targeted application by continuously flooding the endpoint with the exploit payload. This affects all public-facing applications built on the vulnerable versions of the Qwik framework.

## Recommendation

* Patch the vulnerability by upgrading @builder.io/qwik to version 1.20.0 or later, or @qwik.dev/core to 2.0.0-beta37 or later.
* Monitor web server logs for high frequencies of 500-series status codes coinciding with process restarts.
* Implement rate limiting at the WAF or reverse proxy level to mitigate the impact of the exploit while patching is pending.
* Ensure that the application runtime is configured to capture and log unhandled promise rejections for visibility, although this will not prevent the process crash.
