---
brief_id: brief-2026-11-02-fastify-http-proxy-bypass
event_id: brief-2026-11-02-fastify-http-proxy-bypass
revision: 1
activity_at: "2026-11-02T11:28:52Z"
title: 'Fastify: Path restriction bypass in @fastify/http-proxy (CVE-2026-120213)'
slug: 2026-11-fastify-http-proxy-bypass
description: The @fastify/http-proxy plugin fails to re-encode parameterized route parameters when using rewritePrefix, allowing remote attackers to inject path separators or delimiters to bypass path restrictions and access unauthorized upstream resources.
date: "2026-11-02T11:28:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source documentation confirmed; vulnerability limited to specific plugin versions.
cpes:
  - cpe:2.3:a:fastify:http-proxy:*:*:*:*:*:node.js:*:*
vendors:
  - Fastify
products:
  - '@fastify/http-proxy (9.0.0 - 11.6.5)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can use this to reach upstream locations outside the intended prefix, leading to path-restriction bypass and, depending on the upstream, server-side request forgery or authorization bypass in the proxied service.
    confidence_band: high
cves:
  - id: CVE-2026-120213
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120213
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade @fastify/http-proxy to version 11.6.6 or later
      owner: IT Operations
      due: 24h
      evidence: The issue is fixed in @fastify/http-proxy 11.6.6, and users should upgrade to 11.6.6 or later.
  hunt_leads:
    - lead: Identify usage of parameterized rewritePrefix configurations in Fastify deployments
      technique_id: T1190
      data_needed:
        - Application configuration files (Fastify registration settings)
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: In versions 9.0.0 through 11.6.5, when an application uses parameterized prefix and rewritePrefix options to pin clients to a fixed upstream path, the plugin substitutes URL-decoded route parameters into rewritePrefix without re-encoding them.
  mitigation_plan:
    - priority: immediate
      action: Upgrade @fastify/http-proxy to 11.6.6
      owner: IT Operations
      addresses: CVE-2026-120213
      evidence: The issue is fixed in @fastify/http-proxy 11.6.6
---

The @fastify/http-proxy plugin, versions 9.0.0 through 11.6.5, contains a path-restriction bypass vulnerability. When the plugin is configured with parameterized prefix and rewritePrefix options, it fails to correctly re-encode URL-decoded parameters before they are used in the upstream proxy path. An attacker can inject URL-encoded path separators (e.g., %2f) or query delimiters that decode into active separators on the server, allowing the proxy to direct requests to unintended upstream endpoints. This flaw enables SSRF and authorization bypass in backend services that rely on the proxy to enforce path constraints.

## Impact

The vulnerability allows unauthenticated remote attackers to reach upstream locations outside the intended prefix. Observed impacts include path-restriction bypass, server-side request forgery (SSRF), and potential authorization bypass in the proxied service.

## Recommendation

Upgrade @fastify/http-proxy to version 11.6.6 or later immediately. There are no available workarounds; patching is required to address the injection flaw.
