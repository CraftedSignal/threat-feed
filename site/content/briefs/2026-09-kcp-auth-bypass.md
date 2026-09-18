---
title: Authentication Bypass and Privilege Escalation in kcp Front-Proxy
slug: 2026-09-kcp-auth-bypass
description: The kcp front-proxy fails to sanitize inbound X-Remote-* identity headers, allowing authenticated attackers to perform privilege escalation to system:masters and bypass multi-tenant authorization.
date: "2026-09-18T19:48:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:kcp-dev:kcp:*:*:*:*:*:*:*:*
vendors:
  - kcp-dev
products:
  - kcp (< 0.31.4, >= 0.32.0, < 0.32.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An authenticated attacker could smuggle forged identity headers through to the shard, allowing a low-privilege user to escalate to cluster administrator (system:masters).
    confidence_band: high
cves:
  - id: CVE-2026-61682
    cvss: 9.9
references:
  - https://github.com/advisories/GHSA-c8w2-fgvx-vhv4
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61682
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade kcp deployments to v0.31.4 or v0.32.2 to remediate CVE-2026-61682
      owner: IT Operations
      due: 24h
      evidence: Fixed in v0.31.4, 0.32.2.
  mitigation_plan:
    - priority: immediate
      action: Configure upstream proxy to strip all inbound X-Remote-* headers before reaching kcp front-proxy
      owner: IT Operations
      addresses: CVE-2026-61682
      evidence: Deployments that terminate client connections at an external proxy capable of stripping X-Remote-* headers can mitigate exposure.
---

The kcp-dev kcp platform contains a critical vulnerability (CVE-2026-61682) where the front-proxy fails to remove client-supplied `X-Remote-*` identity headers before forwarding requests to backend shards. In a kcp sharded architecture, the front-proxy authenticates users and communicates their identity to shards via these headers. Because the front-proxy performs an insecure append operation rather than a replace/sanitize operation, an authenticated attacker can inject their own forged headers into the request.

By crafting requests with custom `X-Remote-Group` or `X-Remote-Extra-*` headers, an attacker can assert elevated privileges, specifically `system:masters`, or forge warrants and scopes to break workspace isolation. This allows any authenticated user to gain cluster-administrator access, enabling read, write, and delete operations across all tenants and workspaces managed by the affected shard. The vulnerability was identified and disclosed in September 2026 and affects specific versions of the kcp binary.

## Attack Chain

1. Attacker obtains valid low-privilege authentication credentials (e.g., client certificate, OIDC token, or service account token) valid for the kcp environment.
2. Attacker crafts an HTTP request targeting a resource managed by a kcp shard.
3. Attacker injects malicious `X-Remote-Group: system:masters` and `X-Remote-Extra-*` headers into the request.
4. Attacker sends the crafted request to the kcp front-proxy.
5. Front-proxy authenticates the attacker but fails to strip the pre-existing, malicious identity headers.
6. Front-proxy forwards the request along with the original injected headers to the target shard.
7. The shard processes the identity headers as trusted assertions from the front-proxy.
8. Attacker gains unauthorized administrative access to the targeted workspace or the entire shard, allowing data exfiltration or destructive actions.

## Impact

Successful exploitation results in a total breakdown of multi-tenant security boundaries within a kcp cluster. An attacker can access, modify, or delete any resource, including secrets, APIExports, and LogicalClusters, across all workspaces on the compromised shard. The potential impact is widespread data breach and full cluster takeover, affecting any organization utilizing sharded kcp deployments for multi-tenant service hosting.

## Recommendation

Prioritize the immediate upgrade of all kcp front-proxy and shard components to version 0.31.4 or 0.32.2. No configuration changes are required following the patch. In environments where immediate patching is not feasible, implement a strict front-end proxy layer (e.g., Nginx, Envoy, or HAProxy) positioned before the kcp front-proxy that explicitly strips all `X-Remote-` prefixed headers from inbound client requests. Monitor webserver logs for requests containing headers such as `X-Remote-Group` or `X-Remote-Extra` originating from client IP addresses to identify potential exploitation attempts.
