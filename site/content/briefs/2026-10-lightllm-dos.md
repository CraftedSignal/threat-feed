---
title: Denial of Service Vulnerability in LightLLM
slug: 2026-10-lightllm-dos
description: LightLLM versions through 1.2.0 are susceptible to an unauthenticated denial-of-service attack via the /generate endpoint caused by unsafe deserialization.
date: "2026-10-15T20:40:31Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:lightllm:lightllm:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - web-application
vendors:
  - LightLLM
products:
  - LightLLM (<= 1.2.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: LightLLM through 1.2.0 contains a denial of service vulnerability that allows unauthenticated attackers to crash the inference worker by supplying the internal pd_kv_trans_params field to the /generate endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-111160
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111160
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict access to the /generate API endpoint to trusted internal networks only
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows unauthenticated attackers to crash service
  mitigation_plan:
    - priority: immediate
      action: Upgrade LightLLM to a version beyond 1.2.0
      owner: IT Operations
      addresses: CVE-2026-111160
      evidence: NVD vulnerability report
---

LightLLM versions through 1.2.0 contain a critical denial-of-service vulnerability that allows unauthenticated attackers to crash the inference worker. The vulnerability resides in the /generate endpoint, specifically within the handling of the internal pd_kv_trans_params field. By supplying a specially crafted payload in this parameter, an attacker triggers a failure in the pickle.loads function within the InferSamplingParams logic. This crash effectively terminates the inference thread. While the /health endpoint remains responsive, all subsequent legitimate requests to the inference service will hang, requiring a manual service restart to restore normal operations. This flaw represents a significant risk for deployments relying on LightLLM for inference tasks.

## Impact

The vulnerability impacts any infrastructure running LightLLM versions up to and including 1.2.0. Successful exploitation results in a complete service outage for inference workloads. Because the /health check does not reflect the failure of the underlying inference thread, monitoring systems may fail to detect the outage immediately, potentially leading to prolonged periods of service unavailability for end users.

## Recommendation

Patching is required to mitigate this risk. Ensure all LightLLM deployments are updated beyond version 1.2.0 to resolve the deserialization flaw. Until an update is applied, ensure that access to the /generate endpoint is restricted via network-level controls such as a Web Application Firewall or API gateway to prevent unauthenticated requests from reaching the vulnerable endpoint.
