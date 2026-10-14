---
title: Kubeflow Model Registry Server-Side Request Forgery
slug: 2026-10-kubeflow-ssrf
description: Kubeflow Model Registry versions up to 0.3.17 contain a server-side request forgery vulnerability allowing namespace users to exfiltrate ServiceAccount tokens and gain cluster-wide privileges.
date: "2026-10-14T04:38:35Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kubeflow:model_registry:*:*:*:*:*:*:*:*
tags:
  - kubernetes
  - ssrf
  - cloud-native
  - kubeflow
vendors:
  - Kubeflow
products:
  - Model Registry (<= 0.3.17)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers can create an InferenceService pointing the annotation at their server, capture the bearer token, and modify other tenants' InferenceServices cluster-wide.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Kubeflow Model Registry through 0.3.17 contains a server-side request forgery vulnerability that allows namespace users to steal the controller ServiceAccount token.
    confidence_band: high
cves:
  - id: CVE-2026-110220
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110220
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade Kubeflow Model Registry to a version greater than 0.3.17
      owner: IT Operations
      addresses: CVE-2026-110220
      evidence: Source reporting identifies versions through 0.3.17 as vulnerable.
---

Kubeflow Model Registry versions through 0.3.17 are susceptible to a server-side request forgery (SSRF) vulnerability identified as CVE-2026-110220. The flaw resides in the handling of the 'modelregistry.kubeflow.org/url' annotation. A malicious actor with standard namespace-level access can manipulate this annotation to force the controller service to make arbitrary outbound HTTP requests. By pointing this annotation to an attacker-controlled listener, the controller transmits its bearer token, which is often a high-privilege ServiceAccount token. Successful exploitation grants the attacker the ability to manage or modify InferenceServices across the entire Kubernetes cluster, effectively breaking tenant isolation and compromising the platform's control plane.

## Impact

Successful exploitation allows a low-privileged user to escalate their access to cluster-wide control over InferenceServices. This leads to unauthorized data access, potential exfiltration of proprietary machine learning models, and the ability to manipulate service deployments across multiple tenants. The severity of this vulnerability is rated as 7.1 (High) on the CVSS v3.1 scale.

## Recommendation

* Immediately upgrade Kubeflow Model Registry to a version beyond 0.3.17 to remediate CVE-2026-110220.
* Audit Kubernetes ServiceAccount permissions to ensure the controller ServiceAccount follows the principle of least privilege.
* Implement egress network policies to restrict the ability of the Model Registry controller to initiate outbound connections to unauthorized internal or external endpoints.
