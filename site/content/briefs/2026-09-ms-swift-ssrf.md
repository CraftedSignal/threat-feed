---
title: Server-Side Request Forgery in ms-swift
slug: 2026-09-ms-swift-ssrf
description: An unauthenticated server-side request forgery (SSRF) vulnerability in ms-swift version 4.5.2 allows attackers to perform unauthorized requests to internal network services and cloud metadata endpoints.
date: "2026-09-04T15:31:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ms_swift:ms_swift:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - ssrf
vendors:
  - ms-swift
products:
  - ms-swift (4.5.2)
cves:
  - id: CVE-2026-85686
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85686
rules:
  - title: Detect CVE-2026-85686 Exploitation Attempt
    description: Detects potential SSRF exploitation attempts by monitoring HTTP requests to the ms-swift API containing internal or cloud-specific IP addresses in media URL parameters
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit and restrict egress traffic from servers hosting ms-swift 4.5.2
      owner: IT Operations
      due: 24h
      evidence: Source identifies SSRF vulnerability in API deployment
  mitigation_plan:
    - priority: immediate
      action: Upgrade or replace ms-swift 4.5.2
      owner: IT Operations
      addresses: CVE-2026-85686
      evidence: NVD vulnerability disclosure
---

The ms-swift software, specifically version 4.5.2, contains a critical server-side request forgery (SSRF) vulnerability within its OpenAI-compatible deployment API. The flaw stems from the application's failure to validate or filter media URLs before fetching them from remote sources. Attackers can exploit this by supplying malicious inputs into the 'image_url', 'audio_url', or 'video_url' parameters. When the application processes these parameters, it makes an outbound request to the specified destination. Because these requests lack redirect filtering or destination validation, unauthenticated remote attackers can leverage the affected server to interact with internal resources, probe sensitive network services, or query cloud metadata services (such as the IMDS endpoint at 169.254.169.254) to exfiltrate credentials or configuration metadata. This vulnerability poses a significant risk to organizations running internal services in cloud-hosted environments.

## Impact

Successful exploitation allows unauthenticated attackers to perform unauthorized requests on behalf of the vulnerable server, potentially leading to the discovery of internal infrastructure, unauthorized access to internal services, or the exfiltration of sensitive cloud instance identity and configuration data.

## Recommendation

Prioritized actions for security and infrastructure teams:
- Identify all instances of ms-swift 4.5.2 within the environment and restrict their access to internal network resources and cloud metadata endpoints until a patch is applied.
- Review web server access logs for requests containing suspicious 'image_url', 'audio_url', or 'video_url' parameters that point to internal IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or local loopback addresses (127.0.0.1).
- Block or monitor outbound traffic from ms-swift deployment servers to common cloud metadata endpoints (169.254.169.254) using firewall or Egress filtering.
