---
title: Authentication Bypass in F5 NGINX Kubernetes Ingress Controller
slug: 2026-10-nginx-ingress-auth-bypass
description: An authentication and authorization bypass in F5 NGINX Kubernetes Ingress Controller (NIC) allows remote attackers to spoof request attributes and access protected paths by manipulating unsanitized X-Forwarded-* headers.
date: "2026-10-14T16:38:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:f5:nginx_kubernetes_ingress_controller:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ingress
  - kubernetes
vendors:
  - F5
products:
  - NGINX Kubernetes Ingress Controller
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authentication and authorization bypass vulnerability exists in F5 NGINX Kubernetes Ingress Controller (NIC) when configured with the ExternalAuth policy.
    confidence_band: high
cves:
  - id: CVE-2026-94197
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94197
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade NGINX Kubernetes Ingress Controller to the vendor-recommended fixed version.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-94197 vulnerability requires patching.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict access to backend paths relying solely on ExternalAuth if immediate patching is not possible.
      owner: Security Engineering
      addresses: CVE-2026-94197
      evidence: NVD vulnerability details regarding authentication bypass.
---

F5 NGINX Kubernetes Ingress Controller (NIC) is vulnerable to an authentication and authorization bypass when configured with the ExternalAuth policy or Ingress external authentication. The vulnerability stems from the improper sanitization of client-supplied HTTP headers, specifically X-Forwarded-Prefix, X-Forwarded-URI, X-Original-URI, and X-Forwarded-Method. These headers are forwarded into the internal authentication subrequest handled by the NGINX auth_request directive. Because the ingress controller trusts these headers without sanitization, a remote, unauthenticated attacker can manipulate them to spoof request attributes evaluated by the external authentication provider. This flaw resides strictly in the data plane and does not expose the control plane, yet it permits unauthorized access to sensitive backend resources protected by the ingress controller.

## Impact

The vulnerability allows unauthenticated remote attackers to bypass security constraints and gain access to protected paths managed by the affected Kubernetes Ingress Controller. This constitutes a significant security risk for organizations relying on NIC for traffic management and path-level access control, potentially leading to unauthorized data exposure or interaction with internal microservices that assume authentication has been successfully validated at the ingress layer.

## Recommendation

1. Inventory all ingress controller deployments to determine if the ExternalAuth policy or Ingress external authentication is active.
2. Monitor ingress traffic for anomalous HTTP headers, particularly where X-Forwarded-* headers contain unexpected characters or values inconsistent with the request path.
3. Consult the F5 security advisory to identify patched versions of NGINX Kubernetes Ingress Controller and perform upgrades in all affected clusters.
4. Implement strict header validation at the application level or via service mesh sidecars as a compensating control while the ingress controller is being patched.
