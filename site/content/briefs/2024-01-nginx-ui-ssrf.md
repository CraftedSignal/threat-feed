---
title: Nginx-UI SSRF Vulnerability via Cluster Node Proxy
slug: 2024-01-nginx-ui-ssrf
description: Nginx-UI version 2.3.4 and earlier is vulnerable to Server-Side Request Forgery (SSRF) allowing authenticated users to access internal services by manipulating cluster node configurations.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - nginx-ui
  - web-application
vendors:
  - 0xJacky
products:
  - Nginx-UI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-wr32-99hh-6f35
rules:
  - title: Detect Nginx-UI SSRF via X-Node-ID Header
    description: Detects potential SSRF attempts in Nginx-UI by monitoring for requests with the X-Node-ID header, indicating the use of the proxy middleware.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Nginx-UI Malicious Node Creation
    description: Detects the creation of cluster nodes with suspicious URLs, such as internal IP addresses, which may indicate an SSRF attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Nginx-UI versions 2.3.4 and earlier contain a Server-Side Request Forgery (SSRF) vulnerability in the cluster node proxy middleware. An authenticated user can exploit this flaw by creating a malicious cluster node that points to an arbitrary internal URL, such as localhost services or cloud metadata endpoints. The vulnerability lies in the lack of validation for the node URL within the `internal/middleware/proxy.go` file. Successful exploitation allows attackers to bypass network segmentation, access sensitive internal resources, and potentially escalate privileges, especially when combined with other vulnerabilities like njs code injection. This issue allows attackers to reach internal services that should not be exposed.

## Attack Chain

1. Attacker authenticates to the Nginx-UI web interface.
2. Attacker retrieves the `node_secret` via a `GET` request to `/api/settings`.
3. Attacker crafts a `POST` request to `/api/nodes` to create a new cluster node.
4. The crafted node configuration includes a malicious `url` parameter pointing to an internal resource (e.g., `http://127.0.0.1:51820` or `http://169.254.169.254`).
5. Attacker sends an API request (e.g., `GET /api/settings`) with the `X-Node-ID` header set to the ID of the newly created malicious node.
6. The Nginx-UI proxy middleware (`internal/middleware/proxy.go`) intercepts the request and forwards it to the attacker-specified internal URL.
7. The request is executed on the server-side, effectively performing an SSRF attack.
8. Attacker gains access to internal resources, cloud metadata, or triggers internal-only njs endpoints.

## Impact

Successful exploitation allows an authenticated attacker to access internal services, cloud metadata endpoints, and internal-only njs endpoints. This can lead to the theft of sensitive information such as IAM credentials, port scanning of internal networks, and ultimately, remote code execution and privilege escalation if combined with other vulnerabilities. This vulnerability bypasses network segmentation and firewalls designed to restrict inbound traffic, potentially exposing critical internal resources.

## Recommendation

*   Deploy the Sigma rule `Detect Nginx-UI SSRF via X-Node-ID Header` to identify requests with the `X-Node-ID` header that may indicate SSRF attempts.
*   Deploy the Sigma rule `Detect Nginx-UI Malicious Node Creation` to detect the creation of cluster nodes with suspicious URLs (e.g., internal IPs).
*   Monitor network connections originating from the Nginx-UI server to internal IPs and cloud metadata endpoints using existing network monitoring tools.
