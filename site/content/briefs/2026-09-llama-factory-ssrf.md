---
title: 'CVE-2026-85673: SSRF Vulnerability in LLaMA-Factory OpenAI-Compatible API'
slug: 2026-09-llama-factory-ssrf
description: LLaMA-Factory is vulnerable to server-side request forgery (SSRF) due to improper validation of multimodal media URLs in its OpenAI-compatible API, allowing unauthenticated attackers to access internal network resources.
date: "2026-09-04T15:30:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:llama_factory:llama_factory:*:*:*:*:*:*:*:*
vendors:
  - LLaMA-Factory
products:
  - LLaMA-Factory (unspecified version)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: LLaMA-Factory contains a server-side request forgery vulnerability in the OpenAI-compatible API multimodal media URL handler that allows unauthenticated attackers to bypass SSRF validation.
    confidence_band: high
cves:
  - id: CVE-2026-85673
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85673
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review egress traffic from application servers to identify attempts to reach internal IP ranges or cloud metadata IPs.
      owner: SOC
      due: 24h
      evidence: The vulnerability enables attackers to access internal addresses and cloud metadata endpoints.
  mitigation_plan:
    - priority: immediate
      action: Apply network egress controls preventing the application server from accessing internal infrastructure or cloud metadata services.
      owner: IT Operations
      addresses: CVE-2026-85673
      evidence: The vulnerability is an SSRF flaw that allows access to internal network resources.
---

LLaMA-Factory contains a server-side request forgery (SSRF) vulnerability within its OpenAI-compatible API's multimodal media URL handler (CVE-2026-85673). The issue stems from the 'check_ssrf_url' guard, which performs a one-time validation of the user-supplied URL. However, the application uses 'requests.get' to fetch these URLs, which follows HTTP redirects and performs subsequent DNS resolutions without re-validating the final, resolved destination. This flaw permits unauthenticated attackers to bypass security controls using techniques such as HTTP redirection or DNS rebinding. By exploiting this, attackers can force the LLaMA-Factory instance to perform requests to sensitive internal network addresses or cloud metadata service endpoints, potentially leading to unauthorized data access or internal reconnaissance.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to interact with internal network services that are otherwise inaccessible from the public internet. This includes access to cloud metadata services (e.g., 169.254.169.254), internal management interfaces, and other microservices within the hosting environment. The potential impact involves unauthorized data exfiltration, service manipulation, or leveraging the application as a proxy for lateral movement within the infrastructure.

## Recommendation

- Monitor application logs for anomalous outbound HTTP requests originating from the LLaMA-Factory server, particularly those targeting internal IP ranges or cloud metadata endpoints.
- Implement network-level egress filtering to prevent the LLaMA-Factory application from reaching sensitive internal segments or the cloud provider metadata service.
- Review vendor documentation for patches addressing CVE-2026-85673 and update the LLaMA-Factory deployment to a non-vulnerable version as soon as one is released.
