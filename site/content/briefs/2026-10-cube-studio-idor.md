---
title: Insecure Direct Object Reference in Cube-studio
slug: 2026-10-cube-studio-idor
description: An insecure direct object reference vulnerability in Cube-studio versions through 2026.09.01 allows authenticated users to perform unauthorized administrative actions on notebooks and services via sequential ID manipulation.
date: "2026-10-16T18:49:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:cube-studio:cube-studio:*:*:*:*:*:*:*:*
vendors:
  - Cube-studio
products:
  - Cube-studio (<= 2026.09.01)
cves:
  - id: CVE-2026-111671
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111671
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Review internal Cube-studio instances and verify version is post-2026.09.01
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-111671
  mitigation_plan:
    - priority: immediate
      action: Upgrade Cube-studio to the latest patched release
      owner: IT Operations
      addresses: CVE-2026-111671
      evidence: NVD vulnerability disclosure
---

Cube-studio versions through 2026.09.01 are vulnerable to an Insecure Direct Object Reference (IDOR) flaw located within its lifecycle management endpoints. Specifically, the affected files `view_notebook.py`, `view_inferenceserving.py`, and `view_serving.py` fail to properly authorize users before executing lifecycle commands on requested resource IDs. An authenticated attacker can exploit this by passing sequential integer identifiers to these endpoints, allowing them to stop, reset, clear, or redeploy notebooks and services belonging to other users. This vulnerability is critical for production environments, as successful exploitation enables an attacker to delete pods and take critical inference endpoints offline, resulting in a denial-of-service for legitimate services.

## Impact

The vulnerability allows unauthorized control over arbitrary notebooks and services within a shared Cube-studio environment. An attacker with standard user access can cause widespread disruption by terminating production-critical inference endpoints and deleting Kubernetes pods. The scope of impact is limited to organizations hosting multi-user environments where notebook or service isolation relies on the integrity of the Cube-studio access control logic.

## Recommendation

1. Upgrade Cube-studio to a version beyond 2026.09.01 once a patch is provided by the vendor.
2. Implement strict access control validation at the application layer for all lifecycle endpoints in `view_notebook.py`, `view_inferenceserving.py`, and `view_serving.py`.
3. Monitor web server logs for anomalous patterns of sequential ID requests to lifecycle management endpoints from authenticated user sessions.
4. Restrict access to the Cube-studio dashboard to trusted networks or implement mTLS to reduce the risk of unauthorized authenticated access.
