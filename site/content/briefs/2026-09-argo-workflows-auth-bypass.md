---
title: Authorization Bypass in Argo Workflows ListArchivedWorkflows
slug: 2026-09-argo-workflows-auth-bypass
description: Argo Workflows versions 4.1.0 through 4.1.3 contain an authorization bypass vulnerability in ListArchivedWorkflows allowing unauthorized access to workflow metadata via crafted namespace field selectors.
date: "2026-09-20T00:15:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:argoproj:argo_workflows:4.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:argoproj:argo_workflows:4.1.1:*:*:*:*:*:*:*
  - cpe:2.3:a:argoproj:argo_workflows:4.1.2:*:*:*:*:*:*:*
  - cpe:2.3:a:argoproj:argo_workflows:4.1.3:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cloud
  - authorization-bypass
vendors:
  - Argo Project
products:
  - Argo Workflows (4.1.0-4.1.3)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: This allows an attacker with limited namespace-scoped permissions to perform unauthorized data exfiltration, specifically retrieving archived workflow specifications, parameters, and annotations from namespaces they should not have access to.
    confidence_band: high
cves:
  - id: CVE-2026-93991
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93991
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Argo Workflows to the patched version as defined by Argo Project.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-93991 patch requirement.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Argo Workflows to latest version
      owner: IT Operations
      addresses: CVE-2026-93991
      evidence: NVD vulnerability disclosure
---

Argo Workflows versions 4.1.0 through 4.1.3 are affected by an authorization bypass vulnerability (CVE-2026-93991) within the ListArchivedWorkflows function. The vulnerability stems from an inadequate application of cluster-scoped access reviews when users provide specific field selectors during an API request. Specifically, when a request includes a metadata.namespace field selector utilizing the NotEquals operator, the system fails to restrict the result set to the user's authorized namespace. This flaw allows an authenticated attacker possessing only namespace-scoped list permissions to successfully perform unauthorized data exfiltration. Impacted organizations may see exposure of sensitive information stored in archived workflows, including spec arguments, parameter values, and metadata annotations from namespaces they do not legitimately manage.

## Impact

Successful exploitation leads to unauthorized information disclosure of workflow configurations across a Kubernetes cluster. This can expose sensitive secrets, environment-specific parameters, and architectural details contained within workflow specs that should be protected by RBAC, potentially aiding in further lateral movement or privilege escalation within the cloud environment.

## Recommendation

1. Upgrade Argo Workflows to the latest patched version immediately.
2. Audit Kubernetes RBAC policies to ensure minimal list permissions are applied to namespace-scoped service accounts.
3. Review API access logs for anomalous usage of metadata.namespace field selectors with negation operators.
