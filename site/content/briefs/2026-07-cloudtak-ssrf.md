---
title: Authenticated Full-Read SSRF in CloudTAK /api/esri* Routes
slug: 2026-07-cloudtak-ssrf
description: An authenticated Server-Side Request Forgery (SSRF) vulnerability exists in CloudTAK's `/api/esri*` routes, allowing any authenticated user to compel the server to make arbitrary outbound HTTP requests to internal network resources, enabling attackers to access sensitive cloud instance metadata, enumerate internal services, and exfiltrate data by reflecting the response bodies.
date: "2026-07-17T21:36:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - web-vulnerability
  - credential-access
  - network-discovery
  - cloud-security
vendors:
  - dfpc-coe
products:
  - CloudTAK <= 13.7.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated Server-Side Request Forgery (SSRF) vulnerability exists in CloudTAK's `/api/esri*` routes, allowing any authenticated user to compel the server to make arbitrary outbound HTTP requests to internal network resources.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: 'Internal network enumeration and data exfiltration: any host:port reachable from the CloudTAK server (...) can be probed.'
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: ""
    evidence: 'Cloud credential theft: reading `http://169.254.169.254/latest/meta-data/iam/security-credentials/...` (IMDSv1) yields the instance role''s temporary AWS credentials.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-r95q-fp26-h3hc
iocs:
  - type: ip
    value: 169.254.169.254
  - type: url
    value: http://169.254.169.254/latest/meta-data/iam/security-credentials/arcgis/rest
ioc_counts:
  ip: 1
  url: 1
rules:
  - title: Detect CloudTAK SSRF Attempt via GET /api/esri/*
    description: Detects attempts to exploit the authenticated full-read SSRF vulnerability in CloudTAK's `/api/esri*` routes by submitting internal IP addresses (e.g., loopback, IMDSv1, localhost) as values for `portal`, `server`, or `layer` query parameters. This targets GET requests as described in GHSA-r95q-fp26-h3hc.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
      - initial_access
    techniques:
      - T1082
      - T1190
      - T1552.006
    data_sources:
      - webserver
rules_count: 1
---

A critical authenticated Server-Side Request Forgery (SSRF) vulnerability (GHSA-r95q-fp26-h3hc) has been identified in CloudTAK versions up to and including 13.7.0. The vulnerability resides within the `/api/esri*` family of routes, which process user-controlled URLs without proper IP/DNS classification. This oversight allows any authenticated user to force the CloudTAK server to initiate arbitrary HTTP requests to internal network resources, such as cloud instance metadata services (e.g., AWS IMDSv1 at `169.254.169.254`) or loopback admin ports (`127.0.0.1:<port>`). Unlike blind SSRF, this is a full-read vulnerability, reflecting the upstream response body or error message directly back to the attacker. The issue stems from an incomplete security hardening effort, where an existing `isSafeUrl` guard was implemented in other parts of the application but neglected for the `/api/esri*` routes, which continue to use an unguarded `fetch` function from `@tak-ps/etl`.

## Attack Chain

1. An authenticated attacker (any valid user token) sends an HTTP POST request to `/api/esri` with a malicious `url` parameter in the body, or an HTTP GET request to `/api/esri/*` with malicious `portal`, `server`, or `layer` query parameters.
2. The CloudTAK application receives the request, which contains a crafted URL targeting an internal resource, such as `http://169.254.169.254/latest/meta-data/iam/security-credentials/arcgis/rest`.
3. The application's `EsriBase.sniff()` function performs a path validation, checking for `/rest`, `/arcgis/rest`, or `/sharing/rest` within the URL's pathname, which the crafted URL satisfies.
4. Crucially, no host or IP address validation is performed, allowing internal IP addresses (e.g., `169.254.169.254`, `127.0.0.1`) to pass the check.
5. The CloudTAK server, using the unguarded `fetch` function from `@tak-ps/etl`, makes an outbound HTTP request to the attacker-controlled internal address.
6. The targeted internal service (e.g., AWS IMDSv1, a local admin port, or other VPC-internal services) responds to the CloudTAK server's request.
7. The CloudTAK application captures the full response body or error message from the internal service.
8. The application reflects this sensitive internal information, including potential cloud credentials or internal service configurations, back to the attacker.

## Impact

This full-read Server-Side Request Forgery (CWE-918) carries significant risk. Successful exploitation can lead to cloud credential theft, specifically temporary AWS credentials from IMDSv1 services (`169.254.169.254`), which attackers can then use to access and control cloud resources. Attackers can also perform extensive internal network enumeration, probing any host and port reachable from the CloudTAK server, including loopback admin ports and VPC-internal services. The ability to read full JSON responses allows for data exfiltration of sensitive information from these internal systems. While the vulnerability requires authentication, it does not necessitate administrative privileges, making any authenticated user a potential vector for attack.

## Recommendation

* Deploy the Sigma rule "Detect CloudTAK SSRF Attempt via GET /api/esri/*" to your SIEM to identify suspicious exploitation attempts.
* Monitor web server logs for HTTP GET requests to `/api/esri/*` routes containing internal IP addresses (e.g., 127.0.0.1, 169.254.169.254) or `localhost` within the `portal`, `server`, or `layer` query parameters.
* Patch CloudTAK instances to a version that remediates GHSA-r95q-fp26-h3hc immediately.
* Implement robust egress filtering on network firewalls and security groups to prevent CloudTAK servers from making outbound connections to internal-only IP ranges (e.g., `169.254.169.254`, `127.0.0.1`, RFC1918 addresses) unless absolutely essential and explicitly allowlisted.
