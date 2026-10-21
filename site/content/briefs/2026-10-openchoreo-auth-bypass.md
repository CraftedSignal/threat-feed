---
brief_id: brief-2026-10-21-openchoreo-auth-bypass
event_id: brief-2026-10-21-openchoreo-auth-bypass
revision: 1
activity_at: "2026-10-21T17:06:39Z"
title: 'OpenChoreo: WorkflowRun authorization bypass (CVE-2026-113727)'
slug: 2026-10-openchoreo-auth-bypass
description: OpenChoreo API server allows authenticated users with workflow update permissions to hijack ownership of cross-project WorkflowRuns, leading to unauthorized access to logs, build credentials, and workflow modification.
date: "2026-10-21T17:06:39Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "6"
  rating: A6
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:openchoreo:openchoreo:*:*:*:*:*:*:*:*
tags:
  - auth-bypass
  - privilege-escalation
  - webserver
  - kubernetes
vendors:
  - OpenChoreo
products:
  - openchoreo (1.0.0-1.0.5)
  - openchoreo (1.1.0-1.1.6)
  - openchoreo (1.2.0-1.2.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The OpenChoreo API server authorized PUT .../workflowruns/{runName} against ownership metadata taken from the request body, while the object it actually mutated was selected by the URL path.
    confidence_band: high
cves:
  - id: CVE-2026-113727
    cvss: 7.4
    epss: 0.00434
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-46r4-q7wv-32fc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113727
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit RBAC roles for workflowrun:update permissions and restrict to necessary CI service accounts
      owner: SOC
      due: 24h
      evidence: Workaround provided by GHSA
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenChoreo to 1.0.6, 1.1.7, or 1.2.5
      owner: IT Operations
      addresses: CVE-2026-113727
      evidence: Vendor patch advisory
---

OpenChoreo contains an authorization bypass vulnerability (CVE-2026-113727) in the `PUT .../workflowruns/{runName}` endpoint. The API server incorrectly derives ownership metadata from the request body rather than the stored object when evaluating the `workflowrun:update` permission. Because a WorkflowRun's project and component membership is defined by the `openchoreo.dev/project` and `openchoreo.dev/component` labels, an authenticated caller can manipulate these labels to reassign ownership of a WorkflowRun to a project or component they control. This results in unauthorized access to sensitive build data, logs, and parameters within the same namespace.

## Impact

Successful exploitation allows an attacker to escalate privileges within a namespace. Observed impact includes:
- Unauthorized access to build logs, which may contain source paths, registry destinations, and secrets.
- Access to Kubernetes event streams for hijacked runs.
- Ability to delete arbitrary WorkflowRuns.
- Modification of `spec.workflow.parameters` on pending runs.
- Denial of service by wedging the run in a `ComponentValidationFailed` state.

## Recommendation

- Upgrade OpenChoreo to version 1.0.6 (for 1.0.x), 1.1.7 (for 1.1.x), or 1.2.5 (for 1.2.5). These versions enforce correct authorization checks by loading stored metadata and make ownership labels immutable on update.
- Audit `AuthzRole` and `ClusterAuthzRole` definitions to identify and restrict principals holding `workflowrun:update` permissions.
- Treat credentials associated with the `workload-publisher` system role as high-value, as they carry the necessary permissions for this exploit.
