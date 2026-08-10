---
title: Arbitrary Code Execution in trustyai-service-operator via Sidecar Injection
slug: 2026-08-trustyai-rce
description: An authenticated user within a Kubernetes cluster can exploit the LMEvalJob controller in trustyai-service-operator to bypass security policies via custom sidecar containers, enabling arbitrary code execution.
date: "2026-08-10T21:37:46Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Red Hat
products:
  - trustyai-service-operator
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This allows the user to enable and execute untrusted remote code, leading to arbitrary code execution within the cluster.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: An authenticated user within the cluster can exploit this vulnerability by configuring a sidecar container to bypass existing security policies.
    confidence_band: high
cves:
  - id: CVE-2026-15467
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15467
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review and restrict RBAC permissions for trustyai-service-operator LMEvalJob controller resources.
      owner: IT Operations
      due: 24h
      evidence: Source states authenticated users can exploit the controller to bypass policies.
  mitigation_plan:
    - priority: immediate
      action: Upgrade trustyai-service-operator when vendor patch is released.
      owner: IT Operations
      addresses: CVE-2026-15467
      evidence: NVD vulnerability disclosure.
---

CVE-2026-15467 describes a security flaw within the trustyai-service-operator, specifically affecting the LMEvalJob controller. An authenticated user with existing access to the Kubernetes cluster can manipulate the configuration of the LMEvalJob to inject or configure a sidecar container. By crafting this sidecar configuration, the user can effectively bypass established cluster security policies (such as Pod Security Admissions or Pod Security Policies). This bypass facilitates the execution of arbitrary, untrusted remote code within the context of the cluster, posing a significant risk for lateral movement, data exfiltration, or further compromise of the containerized environment. This vulnerability highlights the importance of restricting access to CRD (Custom Resource Definition) creation and modification in environments utilizing the trustyai-service-operator.

## Impact

Successful exploitation allows an authenticated cluster user to escalate privileges and execute arbitrary commands, potentially compromising the integrity and confidentiality of the entire Kubernetes cluster environment. There are no observed victim counts at this time, but the vulnerability affects all deployments utilizing the vulnerable versions of the trustyai-service-operator.

## Recommendation

- Restrict access to the creation and update operations for the LMEvalJob custom resource to trusted administrative users only.
- Implement and enforce Kubernetes Admission Controllers that validate sidecar container definitions to prevent unauthorized policy bypasses.
- Patch the trustyai-service-operator to the latest version provided by Red Hat as soon as the security update is available.
- Monitor Kubernetes audit logs for suspicious modifications to LMEvalJob resources, specifically focusing on fields related to sidecar configuration.
