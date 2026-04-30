---
title: OpenClaw MS Teams Webhook Resource Exhaustion Vulnerability
slug: 2026-04-openclaw-resource-exhaustion
description: OpenClaw before 2026.3.31 parses MS Teams webhook request bodies before performing JWT validation, allowing unauthenticated attackers to exhaust server resources by sending malicious Teams webhook payloads.
date: "2026-04-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - resource-exhaustion
  - webhook
  - cve-2026-41405
vendors:
  - OpenClaw
products:
  - OpenClaw
cves:
  - id: CVE-2026-41405
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41405
  - https://github.com/openclaw/openclaw/commit/3834d47099dd13c8244ed6de8b9ea9855c553623
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-p464-m8x6-vhv8
  - https://www.vulncheck.com/advisories/openclaw-resource-exhaustion-via-unauthenticated-ms-teams-webhook-body-parsing
rules:
  - title: Detect High Number of Requests to Teams Webhook
    description: Detects a high number of requests to the MS Teams webhook endpoint, potentially indicating a resource exhaustion attack.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
      - resource_exhaustion
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 1
---

OpenClaw before version 2026.3.31 is vulnerable to a resource exhaustion attack due to improper handling of MS Teams webhook requests. The application parses the request body before validating the JWT, which allows unauthenticated attackers to send malicious payloads. By sending specially crafted Teams webhook payloads, attackers can bypass authentication checks and exhaust server resources. This vulnerability, identified as CVE-2026-41405, can lead to denial of service and impacts systems where OpenClaw is used to process MS Teams webhooks. Successful exploitation can severely degrade or halt OpenClaw's functionality.

## Attack Chain

1. An unauthenticated attacker identifies an OpenClaw instance processing MS Teams webhooks.
2. The attacker crafts a malicious MS Teams webhook payload designed to consume excessive resources during parsing.
3. The attacker sends the malicious webhook payload to the OpenClaw endpoint.
4. OpenClaw receives the webhook request and begins parsing the request body *before* JWT validation.
5. The malicious payload triggers excessive resource consumption (CPU, memory) during the parsing stage.
6. The parsing process exhausts available server resources.
7. OpenClaw becomes unresponsive or crashes due to resource exhaustion.
8. Legitimate MS Teams webhook requests are no longer processed, leading to a denial of service.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition, rendering OpenClaw unresponsive. This can disrupt any services relying on OpenClaw for MS Teams webhook processing. While the precise number of affected organizations is unknown, any organization using a vulnerable version of OpenClaw is at risk. The impact includes potential loss of data, interrupted workflows, and reputational damage.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.31 or later to patch CVE-2026-41405.
*   Implement rate limiting on the MS Teams webhook endpoint to mitigate resource exhaustion, even after patching.
*   Monitor web server logs (category `webserver`, product `linux`) for unusual traffic patterns and large request sizes to the MS Teams webhook endpoint.
*   Deploy the Sigma rule `Detect High Number of Requests to Teams Webhook` to identify potential exploitation attempts.
