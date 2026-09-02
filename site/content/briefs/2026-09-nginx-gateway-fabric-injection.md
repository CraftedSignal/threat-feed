---
title: 'CVE-2026-66362: Injection Vulnerability in NGINX Gateway Fabric'
slug: 2026-09-nginx-gateway-fabric-injection
description: An injection vulnerability in the NGINX Gateway Fabric configuration generator allows authenticated users to inject arbitrary NGINX directives into the configuration when using NGINX Plus as the data plane.
date: "2026-09-02T17:15:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:nginx:gateway_fabric:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - kubernetes
  - ingress
  - injection
vendors:
  - NGINX
products:
  - NGINX Gateway Fabric
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated attacker with permission to create or modify these resources may craft values that inject arbitrary NGINX configuration directives.
    confidence_band: high
cves:
  - id: CVE-2026-66362
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66362
action_plan:
  priority: elevated
  owners:
    - Cloud Security Team
    - Kubernetes Administrators
  immediate_actions:
    - action: Restrict Kubernetes RBAC permissions for modifying Authentication Filter CRDs.
      owner: Kubernetes Administrators
      due: 48h
      evidence: Source notes that authenticated attackers with modify permissions can exploit the flaw.
  mitigation_plan:
    - priority: immediate
      action: Monitor for unexpected updates to Authentication Filter CRDs or Secrets.
      owner: Cloud Security Team
      addresses: CVE-2026-66362
      evidence: Exploitation requires modification of specific resource fields.
---

CVE-2026-66362 describes an injection vulnerability within the NGINX Gateway Fabric, specifically affecting the configuration generator component. When NGINX Plus is utilized as the data plane, user-supplied strings provided in the 'clientID' or 'cookieName' fields of an Authentication Filter Custom Resource Definition (CRD), or the 'clientSecret' field within a referenced Secret, are not properly sanitized or escaped. These values are rendered directly into NGINX configuration templates. An authenticated attacker who possesses the necessary Kubernetes role-based access control (RBAC) permissions to create or modify these specific resource types can inject arbitrary NGINX directives. This issue is strictly contained within the control plane, allowing for configuration-level manipulation rather than direct data plane exposure.

## Impact

Successful exploitation allows an authenticated attacker to manipulate the NGINX control plane. This could lead to a denial of service, modification of request routing, or unauthorized bypasses of authentication logic, depending on the specific directives injected. The vulnerability is scoped to environments where NGINX Gateway Fabric is deployed with NGINX Plus as the data plane, impacting users of the Kubernetes-native ingress infrastructure.

## Recommendation

- Audit Kubernetes RBAC policies to restrict who can create or modify Authentication Filter CRDs and associated Secrets.
- Prioritize monitoring and validation of Kubernetes resource changes associated with NGINX Gateway Fabric.
- Review the official NGINX security advisory for this CVE to confirm patch availability and upgrade instructions for NGINX Gateway Fabric.
