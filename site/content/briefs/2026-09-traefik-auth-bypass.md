---
title: Traefik Kubernetes Provider Authentication Bypass
slug: 2026-09-traefik-auth-bypass
description: A vulnerability in the Traefik Kubernetes ingress-nginx provider allows unauthenticated access to backend services by bypassing middleware when specific host and annotation configurations are used.
date: "2026-09-10T15:08:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*
vendors:
  - Traefik Labs
products:
  - Traefik (>= 3.7.0, <= 3.7.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The provider mishandles Ingresses that carry both an authentication annotation and the nginx.ingress.kubernetes.io/from-to-www-redirect annotation, allowing unauthorized access.
    confidence_band: high
cves:
  - id: CVE-2026-88877
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88877
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Traefik instances to v3.7.12
      owner: IT Operations
      due: 24h
      evidence: Source advisory states the issue is fixed in v3.7.12
  mitigation_plan:
    - priority: immediate
      action: Remove or reconfigure Ingress objects using both authentication and www-redirect annotations
      owner: IT Operations
      addresses: CVE-2026-88877
      evidence: Vulnerability manifests when these two specific annotations are present
---

Traefik (versions v3.7.0 through v3.7.11) contains a vulnerability in its Kubernetes ingress-nginx provider that enables an attacker to bypass critical middleware, including authentication (e.g., BasicAuth) and source-IP allowlisting. The issue arises when an Ingress resource is configured with both an authentication annotation and the 'nginx.ingress.kubernetes.io/from-to-www-redirect' annotation.

Under these conditions, the Traefik provider creates a 'sibling' router that matches based on the host alone. By crafting an HTTP request containing a non-numeric or empty port within the 'Host' header (e.g., 'Host: www.example.com:x'), an attacker can cause the load balancer to select this sibling router instead of the intended parent. Because the RedirectRegex middleware used in the redirection pattern is non-terminal, requests that do not trigger a redirect are forwarded directly to the backend without any security middlewares applied. This allows unauthorized access to services intended to be protected by Traefik. The vulnerability is resolved in Traefik v3.7.12.

## Impact

Successful exploitation allows an unauthenticated attacker to bypass access controls and security policies on protected backend services. This exposes sensitive internal APIs or applications to unauthorized interaction, potentially leading to full system compromise depending on the backend service's own security posture.

## Recommendation

* Upgrade Traefik to v3.7.12 or later immediately to resolve the insecure router creation logic.
* Audit existing Ingress configurations for the simultaneous presence of authentication annotations and 'nginx.ingress.kubernetes.io/from-to-www-redirect' for any services exposed via the Kubernetes provider.
* Monitor webserver access logs for anomalous 'Host' headers containing non-numeric port suffixes that may indicate an attempt to probe for this bypass.
