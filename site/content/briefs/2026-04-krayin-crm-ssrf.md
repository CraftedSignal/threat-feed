---
title: Webkul Krayin CRM SSRF Vulnerability (CVE-2026-38527)
slug: 2026-04-krayin-crm-ssrf
description: A Server-Side Request Forgery (SSRF) vulnerability in Webkul Krayin CRM v2.2.x allows attackers to scan internal resources by sending a crafted POST request to the /settings/webhooks/create endpoint.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-38527
  - ssrf
  - webkul
  - krayin-crm
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2026-38527
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-38527
  - https://github.com/TREXNEGRO/Security-Advisories/tree/main/CVE-2026-38527
  - https://github.com/krayin/laravel-crm
rules:
  - title: Detect Krayin CRM Webhook SSRF Attempt
    description: Detects potential SSRF exploitation attempts against the /settings/webhooks/create endpoint in Krayin CRM by monitoring POST requests with suspicious URL parameters.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Krayin CRM Webhook SSRF Attempt - Internal IP Range
    description: Detects potential SSRF exploitation attempts by identifying requests containing RFC1918 IP addresses in the Webhook URL.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-38527 details a Server-Side Request Forgery (SSRF) vulnerability affecting Webkul Krayin CRM version 2.2.x. The vulnerability is located in the `/settings/webhooks/create` component. An attacker can exploit this flaw by crafting a malicious POST request that forces the server to make requests to internal resources. This can be leveraged to scan internal network infrastructure, potentially revealing sensitive information or accessing internal services that are not meant to be exposed to the outside world. The vulnerability was published on April 14, 2026. Exploitation requires the attacker to be able to send POST requests to the affected endpoint.

## Attack Chain

1. An attacker identifies a Webkul Krayin CRM instance running version 2.2.x.
2. The attacker crafts a POST request targeting the `/settings/webhooks/create` endpoint.
3. The POST request includes a malicious payload in the body, designed to trigger an SSRF vulnerability. This payload could involve specifying a URL for the webhook to call back to.
4. The vulnerable server processes the crafted POST request and attempts to create a new webhook.
5. The server-side component incorrectly handles or sanitizes the URL provided for the webhook callback.
6. As part of the webhook creation process, the server initiates an HTTP request to the attacker-controlled URL or internal resource specified in the crafted POST request.
7. The server successfully connects to the specified resource, potentially revealing information about the internal network or services.
8. The attacker analyzes the response from the internal service or server to gather sensitive information, such as internal hostnames, open ports, or service versions.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-38527) can allow an attacker to enumerate internal network resources, potentially identifying sensitive services and systems. This information can be used to further compromise the target environment, potentially leading to data breaches or system compromise. While the specific number of affected organizations is unknown, any organization using a vulnerable version of Webkul Krayin CRM is at risk.

## Recommendation

*   Apply the necessary patch or upgrade to a version of Webkul Krayin CRM that resolves CVE-2026-38527.
*   Implement strict input validation and sanitization on all user-supplied data, especially URLs, to prevent SSRF attacks.
*   Monitor web server logs for suspicious requests to the `/settings/webhooks/create` endpoint, looking for unusual URLs or request patterns, using the provided Sigma rule.
*   Implement network segmentation to limit the impact of potential SSRF attacks by restricting access to sensitive internal resources.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
