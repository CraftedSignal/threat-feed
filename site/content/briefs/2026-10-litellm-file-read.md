---
brief_id: brief-2026-10-29-litellm-file-read
event_id: brief-2026-10-29-litellm-file-read
revision: 1
activity_at: "2026-10-29T19:49:34Z"
title: 'LiteLLM: Local file read vulnerability in vertex_ai_credentials'
slug: 2026-10-litellm-file-read
description: An authenticated user with the internal_user_viewer role can read arbitrary local files from the LiteLLM proxy runtime by exploiting an incomplete blocklist in the vertex_ai_credentials parameter.
date: "2026-10-29T19:49:34Z"
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
vendors:
  - LiteLLM
products:
  - LiteLLM (< 1.95.0)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: An authenticated LiteLLM proxy user could read arbitrary local files from the proxy runtime by sending a crafted vertex_ai_credentials value to /utils/transform_request.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-g5ff-637f-6q2m
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade LiteLLM to 1.95.0 or later
      owner: IT Operations
      due: 48h
      evidence: Remediation section specifies upgrading to 1.95.0.
  hunt_leads:
    - lead: Identify requests to /utils/transform_request containing vertex_ai_credentials in the request body
      technique_id: T1083
      data_needed:
        - Web server access logs or application-level request logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability is triggered by supplying a crafted vertex_ai_credentials value to /utils/transform_request.
  mitigation_plan:
    - priority: immediate
      action: Upgrade LiteLLM to 1.95.0
      owner: IT Operations
      addresses: LiteLLM Local File Read
      evidence: Upgrade to 1.95.0 or later.
---

LiteLLM contains a vulnerability where the `/utils/transform_request` endpoint fails to properly sanitize the `vertex_ai_credentials` parameter. While `vertex_credentials` was explicitly blocked in the request-body safety checks, the alias `vertex_ai_credentials` was omitted. An authenticated user with the `internal_user_viewer` role can supply a local file path to this parameter, causing the application to read the file and potentially transmit its contents to an attacker-controlled destination.

## Impact

An attacker can read any file accessible by the system user running the LiteLLM process. Sensitive files such as `/proc/self/environ` may contain environment variables, including `LITELLM_MASTER_KEY` and various provider API keys, leading to full administrative compromise of the proxy instance.

## Recommendation

Upgrade the LiteLLM package to version 1.95.0 or later immediately. The updated version includes `vertex_ai_credentials` in the request-body blocklist, mitigating the vulnerability. No configuration workarounds are available for versions prior to 1.95.0.
