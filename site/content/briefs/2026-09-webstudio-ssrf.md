---
title: Unauthenticated SSRF Vulnerability in Webstudio
slug: 2026-09-webstudio-ssrf
description: Webstudio versions through 0.296.0 are vulnerable to unauthenticated SSRF via proxy endpoints, allowing attackers to access internal cloud metadata and services.
date: "2026-09-05T13:31:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:webstudio:webstudio:*:*:*:*:*:*:*:*
tags:
  - webstudio
  - ssrf
  - vulnerability
  - cloud-security
vendors:
  - Webstudio
products:
  - Webstudio (<= 0.296.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Webstudio through 0.296.0 contains an unauthenticated server-side request forgery vulnerability
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Attackers can supply arbitrary URLs to these endpoints to read cloud instance metadata, access internal services, and perform network reconnaissance on the instance infrastructure.
    confidence_band: high
cves:
  - id: CVE-2026-86119
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86119
rules:
  - title: Detect CVE-2026-86119 Exploitation - SSRF via Webstudio Proxy
    description: Detects potential SSRF attempts by monitoring requests to vulnerable Webstudio proxy endpoints containing common metadata or internal address patterns.
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
    - Detection Engineering
  immediate_actions:
    - action: Configure the RESIZE_ORIGIN environment variable to a known-good origin.
      owner: IT Operations
      due: 24h
      evidence: Source notes this configuration unset leads to the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network access from the Webstudio application server to the 169.254.169.254 IP range.
      owner: IT Operations
      addresses: CVE-2026-86119
      evidence: Source warns of cloud instance metadata access.
---

Webstudio through version 0.296.0 contains an unauthenticated Server-Side Request Forgery (SSRF) vulnerability. The flaw exists within the /cgi/image, /cgi/video, and /cgi/asset proxy routes when the RESIZE_ORIGIN environment variable is left unset. Because these endpoints do not properly validate user-supplied URLs before performing a request, an unauthenticated remote attacker can force the application to make arbitrary outbound HTTP requests from the server's context.

This vulnerability allows attackers to bypass network perimeters to access sensitive cloud instance metadata (e.g., AWS IMDS or GCP metadata services), interact with internal services that are not exposed to the internet, and conduct network reconnaissance of the host infrastructure. Defenders should ensure the RESIZE_ORIGIN environment variable is properly configured or upgrade to a patched version once available.

## Impact

Successful exploitation allows for the exfiltration of sensitive cloud provider credentials via metadata services, unauthorized access to internal management interfaces, and infrastructure-wide network mapping. This poses a high risk to organizations hosting Webstudio in cloud environments where instance metadata is accessible.

## Recommendation

- Ensure the RESIZE_ORIGIN environment variable is set to a restricted, known-good value to disable the vulnerable proxy behavior.
- Monitor webserver access logs for anomalous requests to /cgi/ endpoints that contain suspicious URL query parameters or private IP addresses.
- Restrict outbound network access from the Webstudio server to the cloud metadata service IP address (e.g., 169.254.169.254) using host-based firewalls or cloud security groups.
- Apply patches or updates from the vendor as soon as they are released to address the underlying input validation flaw in the proxy routes.
