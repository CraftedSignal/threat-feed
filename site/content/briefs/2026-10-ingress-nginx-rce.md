---
brief_id: brief-2026-10-30-ingress-nginx-rce
event_id: brief-2026-10-30-ingress-nginx-rce
revision: 1
activity_at: "2026-10-30T16:51:40Z"
title: 'Ingress NGINX: Unauthenticated RCE via configuration injection (CVE-2025-1974)'
slug: 2026-10-ingress-nginx-rce
description: A critical RCE vulnerability in the Ingress NGINX admission webhook allows unauthenticated attackers to inject malicious configuration snippets and execute arbitrary code or load malicious libraries.
date: "2026-10-30T16:51:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:kubernetes:ingress-nginx:*:*:*:*:*:*:*:*
vendors:
  - Kubernetes
products:
  - Ingress NGINX (<= 1.11.4, 1.12.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: O admission webhook do ingress-nginx processa objetos Ingress sem autenticacao por padrao.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: O campo nginx.ingress.kubernetes.io/configuration-snippet e injetado diretamente na config do NGINX, permitindo... executar codigo Lua via init_by_lua_block.
    confidence_band: high
cves:
  - id: CVE-2025-1974
    cvss: 9.8
    epss: 0.994
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=58031907-8CCD-59CB-884A-63FA166F534B
  - https://sploitus.com/exploit?id=58031907-8CCD-59CB-884A-63FA166F534B&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Ingress NGINX to 1.11.5+ or 1.12.1+ across all clusters
      owner: IT Operations
      due: 24h
      evidence: Vulnerability remediation requires version upgrade per PoC advisory.
  hunt_leads:
    - lead: Monitor for suspicious Ingress object annotations containing configuration snippets
      technique_id: T1190
      data_needed:
        - Kubernetes Audit Logs (Ingress object create/update events)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers inject configuration via the nginx.ingress.kubernetes.io/configuration-snippet annotation.
  mitigation_plan:
    - priority: immediate
      action: Apply NetworkPolicy to restrict ingress-nginx admission webhook traffic
      owner: IT Operations
      addresses: CVE-2025-1974
      evidence: Webhook typically not exposed externally; restricting access mitigates risk.
---

CVE-2025-1974 is an unauthenticated Remote Code Execution (RCE) vulnerability in the Ingress NGINX admission webhook (typically listening on port 8443). The issue exists because the webhook processes Ingress objects without authentication, allowing attackers to leverage the `nginx.ingress.kubernetes.io/configuration-snippet` annotation to inject configuration directives. This enables execution of arbitrary Lua code or the loading of malicious shared libraries via `ssl_engine` or `load_module`.

## Impact
Successful exploitation grants RCE within the ingress controller pod. Because the admission controller service account typically possesses high-privileged permissions, attackers may be able to read all Kubernetes Secrets within the cluster.

## Recommendation
- Upgrade Ingress NGINX to version 1.11.5 or 1.12.1 or later immediately.
- Implement network policies to restrict access to the admission webhook port (8443) to authorized traffic only.
- Audit Kubernetes Secrets and RBAC permissions associated with the `ingress-nginx` service account.
