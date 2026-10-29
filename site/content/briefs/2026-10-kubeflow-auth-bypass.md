---
brief_id: brief-2026-10-29-kubeflow-auth-bypass
event_id: brief-2026-10-29-kubeflow-auth-bypass
revision: 1
activity_at: "2026-10-29T17:51:14Z"
title: 'Kubeflow Pipelines: API authorization bypass for log access (CVE-2026-118759)'
slug: 2026-10-kubeflow-auth-bypass
description: An authorization bypass in the Kubeflow Pipelines API server allows unauthenticated or unauthorized users to read sensitive logs by manipulating the GET /apis/v1alpha1/runs/{run_id}/nodes/{node_id}/log handler.
date: "2026-10-29T17:51:14Z"
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
cpes:
  - cpe:2.3:a:kubeflow:pipelines:*:*:*:*:*:*:*:*
tags:
  - api-security
  - kubernetes
  - data-exposure
vendors:
  - Kubeflow
products:
  - Kubeflow Pipelines (< 2.18.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Exposed logs can contain sensitive workload data or credentials.
    confidence_band: high
cves:
  - id: CVE-2026-118759
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118759
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Kubeflow Pipelines to version 2.18.0
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in version 2.18.0.
  hunt_leads:
    - lead: Identify unauthorized log access requests to the Kubeflow API
      technique_id: T1592
      data_needed:
        - Kubeflow API server access logs (HTTP GET requests)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The API server GET /apis/v1alpha1/runs/{run_id}/nodes/{node_id}/log handler retrieved logs without authorizing the caller against the selected run.
  mitigation_plan:
    - priority: immediate
      action: Implement strict network policy or external authentication gate for the Kubeflow API server
      owner: IT Operations
      addresses: CVE-2026-118759
      evidence: The handler does not authenticate requests itself, although an external authentication gate or network policy can limit reachability.
---

Kubeflow Pipelines prior to version 2.18.0 contains a vulnerability in the API server log handler. The handler does not perform authorization checks against the requested run ID, allowing any caller with network access to the API server to retrieve logs. For live logs, the vulnerability allows an attacker to specify a node ID as a pod name, which enables cross-namespace log access for pods not associated with the requested run. This can lead to the exposure of sensitive workload data or hardcoded credentials.

## Impact
Unauthorized access to logs across the Kubeflow environment. Observed potential impact includes unauthorized reading of sensitive workload data and exposure of credentials stored within pipeline logs.

## Recommendation
- Upgrade Kubeflow Pipelines to version 2.18.0 or later immediately.
- Evaluate current network policies and authentication gates surrounding the Kubeflow API server to ensure requests are limited to trusted clients, as the API handler does not perform independent authentication.
