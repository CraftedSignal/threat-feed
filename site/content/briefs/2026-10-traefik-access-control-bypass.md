---
brief_id: brief-2026-10-22-traefik-access-control-bypass
event_id: brief-2026-10-22-traefik-access-control-bypass
revision: 1
activity_at: "2026-10-22T03:52:29Z"
title: 'Traefik: Access-control bypass in Kubernetes Ingress NGINX provider (CVE-2026-114636)'
slug: 2026-10-traefik-access-control-bypass
description: Traefik versions prior to 3.7.14 contain an access-control bypass vulnerability in the Kubernetes Ingress NGINX provider that allows unauthenticated access to backends protected by security annotations.
date: "2026-10-22T03:52:29Z"
lastmod: "2026-10-22T03:52:43Z"
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
  validation_status: Source verified; no IOCs or specific log artifacts provided for rule generation.
cpes:
  - cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*
tags:
  - ingress
  - kubernetes
  - access-control
  - cve-2026-114636
  - authentication-bypass
  - webserver
  - traefik
vendors:
  - Traefik Labs
products:
  - Traefik (< 3.7.14)
  - Traefik (v3.2.0-v3.7.13)
  - Traefik (2.11.0 <= 2.11.57)
  - Traefik (3.0.0 <= 3.7.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers reaching the HTTP entry point with the Ingress host can access backends protected by auth-type, auth-url, or whitelist-source-range annotations.
    confidence_band: high
cves:
  - id: CVE-2026-114636
    cvss: 8.7
    kev_status: "false"
  - id: CVE-2026-114637
    kev_status: unknown
  - id: CVE-2026-114642
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114636
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114637
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114642
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Traefik to 3.7.14 or later
      owner: IT Operations
      due: 24h
      evidence: Vulnerability addressed in Traefik v3.7.14
  mitigation_plan:
    - priority: immediate
      action: Implement network-level access control lists (ACLs) to restrict access to affected Ingress entry points
      owner: Network Security
      addresses: CVE-2026-114636
      evidence: Vulnerability allows bypass of internal application-level auth annotations
updates:
  - at: "2026-10-22T03:52:35Z"
    level: L2
    summary: added coverage for Traefik (v3.2.0-v3.7.13)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-114637
  - at: "2026-10-22T03:52:43Z"
    level: L2
    summary: added coverage for Traefik (2.11.0 <= 2.11.57) +1 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-114642
---

Traefik versions prior to 3.7.14 are susceptible to an access-control bypass vulnerability within the Kubernetes Ingress NGINX provider. The vulnerability occurs when an ssl-passthrough Ingress is configured on a non-TLS entry point, causing Traefik to fail to apply critical access-control annotations. Specifically, protections defined via auth-type, auth-url, or whitelist-source-range are ignored. Unauthenticated remote attackers who can reach the HTTP entry point and identify the Ingress host can bypass intended security restrictions to access protected backend services. Exploitation of this vulnerability does not generate logs within the affected Traefik components.

## Impact

Successful exploitation allows unauthenticated attackers to bypass authentication and authorization controls, potentially gaining unauthorized access to internal services or applications protected by Traefik Ingress annotations.

## Recommendation

- Upgrade Traefik to version 3.7.14 or later immediately.
- Audit existing Ingress configurations for ssl-passthrough settings on non-TLS entry points to determine if they utilize auth-type, auth-url, or whitelist-source-range annotations.
- Until patching is complete, restrict network access to the affected Traefik HTTP entry points to authorized sources only at the network or cloud infrastructure layer.
