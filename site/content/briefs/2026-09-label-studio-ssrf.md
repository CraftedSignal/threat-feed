---
title: Label Studio SSRF via Webhook URL Validation Bypass
slug: 2026-09-label-studio-ssrf
description: Label Studio versions up to 1.23.0 are vulnerable to Server-Side Request Forgery due to improper webhook URL validation, allowing authenticated attackers to target internal network services.
date: "2026-09-03T15:22:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:labelstudio:label_studio:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - web-application
  - data-exfiltration
vendors:
  - Label Studio
products:
  - Label Studio (<= 1.23.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Label Studio through 1.23.0 fails to validate webhook URLs, allowing authenticated users to dispatch requests to internal services.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: Attackers can create webhooks targeting private networks and exfiltrate annotation data by enabling payload transmission in outbound requests.
    confidence_band: high
cves:
  - id: CVE-2026-85179
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85179
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all Label Studio deployments and identify versions <= 1.23.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-85179 vulnerability scope
  mitigation_plan:
    - priority: immediate
      action: Upgrade Label Studio to the latest secure version addressing CVE-2026-85179
      owner: IT Operations
      addresses: CVE-2026-85179
      evidence: NVD vulnerability advisory
---

Label Studio versions through 1.23.0 contain a Server-Side Request Forgery (SSRF) vulnerability due to insufficient validation of webhook URLs. This vulnerability allows an authenticated user to craft malicious webhook requests that reach internal network resources, including those residing on RFC 1918 address spaces and cloud instance metadata services (e.g., 169.254.169.254). 

By manipulating the webhook configuration, an attacker can force the Label Studio server to perform outbound requests on their behalf. This can be weaponized to interact with internal APIs that lack authentication or to exfiltrate sensitive environment configuration data and annotation datasets. The impact is significant for organizations hosting Label Studio within sensitive internal network segments or cloud environments where internal service discovery relies on metadata endpoints.

## Impact

Successful exploitation allows authenticated attackers to bypass network perimeters, potentially leading to unauthorized data exfiltration of sensitive annotations, reconnaissance of internal network infrastructure, and compromise of internal services accessible from the Label Studio host.

## Recommendation

Prioritize the identification and patching of Label Studio instances running version 1.23.0 or earlier. Audit current webhook configurations to identify any entries pointing to internal IP addresses or private domain namespaces.
