---
title: 'CVE-2026-100391: Server-Side Request Forgery in MediaFlow Proxy'
slug: 2026-09-mediaflow-proxy-ssrf
description: MediaFlow Proxy versions 2.4.9 and earlier are vulnerable to server-side request forgery (SSRF) via the /proxy route, allowing unauthorized access to internal resources and cloud metadata services.
date: "2026-09-25T22:55:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mediaflow:proxy:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - web-vulnerability
vendors:
  - MediaFlow
products:
  - MediaFlow Proxy (<= 2.4.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote attackers can supply arbitrary internal URLs including loopback and cloud metadata endpoints to read full responses from the proxy server.
    confidence_band: high
cves:
  - id: CVE-2026-100391
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100391
rules:
  - title: Detect CVE-2026-100391 Exploitation - SSRF via /proxy Endpoint
    description: Detects exploitation of CVE-2026-100391 by monitoring for requests to the /proxy endpoint containing internal IP addresses or cloud metadata service paths in the 'd' query parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade MediaFlow Proxy to a version beyond 2.4.9
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-100391 vulnerability exists in versions through 2.4.9
  mitigation_plan:
    - priority: immediate
      action: Configure WAF rules to sanitize 'd' parameter in /proxy requests
      owner: SOC
      addresses: CVE-2026-100391
      evidence: Missing destination validation in the d query parameter
---

MediaFlow Proxy through version 2.4.9 contains a high-severity server-side request forgery (SSRF) vulnerability. The flaw exists within the /proxy endpoint, where the application fails to perform sufficient validation on the 'd' query parameter. This allows an unauthenticated remote attacker to craft requests that force the proxy server to retrieve data from arbitrary internal or external URLs. 

Defenders must be aware that this vulnerability enables attackers to interact with internal-only services, including loopback (127.0.0.1) addresses and cloud provider metadata services (e.g., 169.254.169.254), to potentially exfiltrate sensitive environment credentials or configuration data. Because this vulnerability exists in the request routing logic, it does not require prior authentication, making it a significant risk for internet-facing instances of MediaFlow Proxy.

## Impact

Successful exploitation allows attackers to bypass network perimeters, probe internal network segments, and access protected cloud instance metadata services, which often contain highly sensitive IAM credentials and environment-specific configuration secrets.

## Recommendation

- Upgrade MediaFlow Proxy to a patched version beyond 2.4.9 immediately to remediate CVE-2026-100391.
- Until patching is complete, restrict access to the /proxy endpoint via Web Application Firewall (WAF) or reverse proxy configurations.
- Audit web server access logs for anomalous requests to the /proxy endpoint that contain internal-only URI schemes, IP addresses, or metadata service paths.
