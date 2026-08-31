---
title: Denial of Service Vulnerability in vLLM
slug: 2026-08-vllm-dos
description: An authenticated remote attacker can exploit a vulnerability in vLLM to trigger a Denial of Service condition, likely through resource exhaustion.
date: "2026-08-24T15:55:42Z"
lastmod: "2026-08-31T11:58:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:hpe:insight_remote_support:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vllm
  - cve-2024-53676
  - availability
vendors:
  - vLLM
products:
  - vLLM
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An authenticated remote attacker can exploit a vulnerability in vllm to perform a Denial of Service attack.
    confidence_band: high
cves:
  - id: CVE-2024-53676
    cvss: 9.8
    epss: 0.51625
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2975
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3083
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review and restrict access to all internet-facing vLLM endpoints to mitigate the requirement for authenticated access.
      owner: IT Operations
      due: 48h
      evidence: The advisory states the attacker must be authenticated to trigger the DoS.
  mitigation_plan:
    - priority: medium_term
      action: Upgrade vLLM to a version containing the patch for CVE-2024-53676.
      owner: IT Operations
      addresses: CVE-2024-53676
updates:
  - at: "2026-08-31T11:58:30Z"
    level: L1
    summary: added coverage for vLLM
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3083
---

A vulnerability has been identified in the vLLM library that allows an authenticated remote attacker to perform a Denial of Service (DoS) attack. The vulnerability, tracked as CVE-2024-53676, enables an attacker with valid authentication to submit crafted input payloads that lead to service interruption or resource exhaustion. Because vLLM is frequently deployed in inference environments where high concurrency and memory usage are standard, successful exploitation can result in the loss of availability for downstream AI-driven applications. Organizations should review their authentication and input validation policies for vLLM endpoints, particularly those exposed to multi-tenant or external user access.

## Impact

The impact of this vulnerability is a Denial of Service, which effectively takes the vLLM inference engine offline. This disrupts the availability of LLM-based services dependent on the engine. If successfully exploited in a production environment, the attack causes service instability or complete failure, requiring a service restart to restore operations.

## Recommendation

* Monitor vLLM logs for authentication patterns associated with frequent or unexpected service restarts.
* Identify and audit all internet-facing instances of vLLM to ensure that access is restricted to authorized users only, as the vulnerability requires authenticated access.
* Update vLLM to the latest version as soon as a patch is available from the project maintainers.
* Implement rate limiting and request size validation at the application or API gateway layer to mitigate potential resource exhaustion attempts.
