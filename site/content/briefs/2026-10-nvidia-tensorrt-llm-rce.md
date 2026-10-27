---
brief_id: brief-2026-10-27-nvidia-tensorrt-llm-rce
event_id: brief-2026-10-27-nvidia-tensorrt-llm-rce
revision: 1
activity_at: "2026-10-27T13:50:36Z"
title: 'NVIDIA TensorRT-LLM: Remote code execution via tokenizer loading vulnerability (CVE-2026-65119)'
slug: 2026-10-nvidia-tensorrt-llm-rce
description: NVIDIA TensorRT-LLM contains an improper tokenizer loading vulnerability that could allow an attacker to achieve remote code execution, information disclosure, data tampering, or denial of service by influencing the control sphere.
date: "2026-10-27T13:50:36Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation once patches are released.
cpes:
  - cpe:2.3:a:nvidia:tensorrt-llm:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - nvidia
  - llm
vendors:
  - NVIDIA
products:
  - TensorRT-LLM
cves:
  - id: CVE-2026-65119
    cvss: 8.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65119
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory TensorRT-LLM deployments.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects TensorRT-LLM product line.
  enrichment_needed:
    - item: Patch release information for CVE-2026-65119
      owner: CTI
      reason: No patch version information available in the source.
      evidence: NVD advisory lacks fixed version.
  hunt_leads:
    - lead: Identify unauthorized access attempts to tokenizer loading components or model configuration paths.
      technique_id: T1190
      data_needed:
        - Application logs
        - File integrity monitoring (FIM) for configuration directories
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability in KvCacheAwareRouter tokenizer loading.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to tokenizer configuration and model loading paths.
      owner: IT Operations
      addresses: CVE-2026-65119
      evidence: Vulnerability stems from untrusted control sphere input.
---

NVIDIA TensorRT-LLM is vulnerable to a flaw in the KvCacheAwareRouter tokenizer loading process. An attacker capable of influencing the input to this component can cause the application to include functionality from an untrusted control sphere. This vulnerability potentially allows for remote code execution, unauthorized information disclosure, data tampering, and denial of service. Specific patch details or firmware versions addressing this issue are not disclosed in the current NVD advisory.

## Impact

Successful exploitation may lead to remote code execution (RCE) on the host environment, unauthorized access to sensitive information, modification of application data, and service interruption.

## Recommendation

1. Inventory all instances of TensorRT-LLM within the environment to assess exposure.
2. Monitor NVIDIA security bulletins for the release of patches addressing CVE-2026-65119.
3. Restrict access to tokenizer configuration files and model loading pipelines to trusted, authenticated users only.
4. Isolate systems running TensorRT-LLM from external or untrusted networks until a security update is applied.
