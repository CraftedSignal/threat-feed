---
title: PraisonAI SSRF Vulnerability via Unvalidated Webhook URL
slug: 2024-01-praisonai-ssrf
description: PraisonAI versions prior to 4.5.128 are vulnerable to Server-Side Request Forgery (SSRF) due to a lack of URL validation on the webhook_url parameter in the /api/v1/runs endpoint, allowing unauthenticated attackers to send arbitrary POST requests from the server.
date: "2026-04-09T22:16:35Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - ssrf
  - praisonai
  - cve-2026-40114
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
cves:
  - id: CVE-2026-40114
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40114
rules:
  - title: Detect Suspicious Webhook URL in PraisonAI Runs Endpoint
    description: Detects suspicious webhook URLs in requests to the /api/v1/runs endpoint of PraisonAI, indicating potential SSRF exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connections from PraisonAI Server to Private IP Ranges
    description: Detects network connections from the PraisonAI server to private IP address ranges, which may indicate SSRF attacks targeting internal resources.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is susceptible to a Server-Side Request Forgery (SSRF) vulnerability affecting versions prior to 4.5.128. The vulnerability resides in the `/api/v1/runs` endpoint, which accepts a `webhook_url` parameter in the request body without proper validation. This allows an unauthenticated attacker to specify an arbitrary URL, causing the PraisonAI server to send an HTTP POST request to that URL upon job completion. This flaw enables attackers to target internal services, cloud metadata endpoints, and other network-adjacent resources, potentially leading to information disclosure, privilege escalation, or denial-of-service. Organizations using affected versions of PraisonAI should upgrade to version 4.5.128 or later to mitigate this risk.

## Attack Chain

1. An unauthenticated attacker identifies a PraisonAI instance running a version prior to 4.5.128.
2. The attacker crafts a malicious HTTP POST request to the `/api/v1/runs` endpoint.
3. The crafted request includes a `webhook_url` parameter containing a URL pointing to an internal service, cloud metadata endpoint, or external attacker-controlled server.
4. The PraisonAI server receives the request and queues a job.
5. The job completes (either successfully or with an error).
6. Upon completion, the server, using `httpx.AsyncClient`, initiates an HTTP POST request to the URL specified in the `webhook_url` parameter.
7. If the `webhook_url` points to an internal service, the attacker can potentially access sensitive information or trigger actions within that service.
8. If the `webhook_url` points to a cloud metadata endpoint, the attacker can retrieve cloud credentials or configuration details.

## Impact

Successful exploitation of this SSRF vulnerability allows an unauthenticated attacker to force the PraisonAI server to make arbitrary HTTP POST requests. This can lead to the exposure of sensitive information from internal services or cloud metadata, potentially granting the attacker unauthorized access to systems and data. The vulnerability could also be leveraged to perform denial-of-service attacks against internal resources. While the exact number of affected organizations is unknown, any organization running a vulnerable version of PraisonAI is at risk.

## Recommendation

*   Upgrade PraisonAI instances to version 4.5.128 or later to remediate CVE-2026-40114.
*   Inspect web server logs for requests to the `/api/v1/runs` endpoint containing suspicious `webhook_url` parameters to detect potential exploitation attempts. Deploy the Sigma rule to detect suspicious webhook URLs.
*   Monitor network traffic for unexpected outbound connections originating from the PraisonAI server to internal or external destinations, as this could indicate SSRF exploitation.
