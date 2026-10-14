---
title: Authentication Bypass in NGINX Ingress Controller
slug: 2026-10-nginx-ingress-auth-bypass
description: NGINX Ingress Controller improperly processes OAuth identity provider responses, potentially allowing unauthenticated attackers to access protected paths via a data plane bypass.
date: "2026-10-14T16:36:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:f5:nginx_ingress_controller:*:*:*:*:*:*:*:*
vendors:
  - F5
products:
  - NGINX Ingress Controller
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: NGINX Ingress Controller may mishandle the HTTP response from an OAuth IdP and allow an attacker to acquire unauthenticated access to protected paths.
    confidence_band: high
cves:
  - id: CVE-2026-104939
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104939
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review ingress configurations for externalAuth policy usage and identify affected ingress resources.
      owner: SOC
      due: 48h
      evidence: Source states vulnerability exists when implementing an externalAuth policy.
  mitigation_plan:
    - priority: immediate
      action: Monitor vendor security advisories and patch NGINX Ingress Controller once the vendor-supplied fix is released.
      owner: IT Operations
      addresses: CVE-2026-104939
      evidence: NVD vulnerability disclosure.
---

The NGINX Ingress Controller contains a vulnerability in its handling of the externalAuth policy, specifically regarding the processing of HTTP responses from OAuth identity providers (IdPs). When configured to use external authentication, the controller may mishandle certain IdP responses, creating a race condition or logic flaw that permits requests to reach protected upstream services before the authentication handshake is successfully completed. This vulnerability is restricted to the data plane and does not expose the Kubernetes control plane. It represents a significant risk for organizations relying on the Ingress Controller to enforce perimeter authentication for internal applications and services.

## Impact

Successful exploitation allows remote, unauthenticated attackers to bypass configured authentication barriers and gain direct access to protected paths. This could lead to unauthorized data access, service disruption, or further exploitation of downstream application vulnerabilities that assumed successful authentication at the ingress layer. The impact is categorized as a high-severity data plane issue.

## Recommendation

Prioritize the identification of all deployments utilizing the externalAuth feature within NGINX Ingress Controller. Audit ingress logs for unusual HTTP response patterns associated with OAuth callback endpoints. Apply security patches provided by F5 for CVE-2026-104939 as soon as they become available for your specific controller version.
