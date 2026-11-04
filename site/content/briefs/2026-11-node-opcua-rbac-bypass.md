---
brief_id: brief-2026-11-04-node-opcua-rbac-bypass
event_id: brief-2026-11-04-node-opcua-rbac-bypass
revision: 1
activity_at: "2026-11-04T00:47:18Z"
title: 'node-opcua: Namespace-level RBAC bypass (CVE-2026-95860)'
slug: 2026-11-node-opcua-rbac-bypass
description: A namespace-level RBAC fail-open vulnerability in node-opcua (CVE-2026-95860) allows unauthenticated network clients to perform unauthorized writes or method calls due to improper role permission inheritance.
date: "2026-11-04T00:47:18Z"
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
cpes:
  - cpe:2.3:a:node-opcua:node-opcua:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rbac
  - opc-ua
  - node-opcua
  - authorization-bypass
products:
  - node-opcua (2.42.0-2.179.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An anonymous network client can consequently write variables with CurrentWrite access or call bound methods when an operator configured a restrictive namespace default and relied on inheritance.
    confidence_band: high
cves:
  - id: CVE-2026-95860
    cvss: 9.1
    kev_status: "false"
references:
  - https://github.com/node-opcua/node-opcua/security/advisories/GHSA-xggf-m53x-jc3f
  - https://github.com/node-opcua/node-opcua/releases/tag/v2.180.0
  - https://github.com/node-opcua/node-opcua/pull/1580
  - https://sploitus.com/exploit?id=CVE-2026-95860&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade node-opcua to version 2.180.0
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in version 2.180.0.
  hunt_leads:
    - lead: Monitor OPC UA server traffic for unauthorized write or method call requests from unauthenticated clients.
      technique_id: T1190
      data_needed:
        - Application-level logs of the OPC UA server
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An anonymous network client can consequently write variables with CurrentWrite access or call bound methods.
  mitigation_plan:
    - priority: immediate
      action: Verify server configurations to ensure per-node permissions are explicitly defined.
      owner: IT Operations
      addresses: CVE-2026-95860
      evidence: Servers with no declared policy, nodes with explicit per-node permissions, and correctly bound programmatic namespace metadata are outside the authorization-bypass case.
---

node-opcua is affected by an authorization bypass vulnerability (CVE-2026-95860) occurring in versions 2.42.0 through 2.179.0. The vulnerability stems from a flaw in `SessionContext.getApplicableRolePermissions`, which fails to correctly read `DefaultRolePermissions` metadata when per-node `RolePermissions` are not explicitly defined. Instead of inheriting restrictive defaults, the runtime treats the missing configuration as permissive. This allows anonymous network clients to write to variables or call bound methods that were intended to be protected by namespace-level access controls.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass namespace-level authorization, granting them the ability to modify variables or execute functions on the OPC UA server that should otherwise be restricted. Servers with no declared default policies, or those using explicit per-node permissions, are not impacted.

## Recommendation

- Upgrade node-opcua to version 2.180.0 or later to patch the underlying logic error.
- Review OPC UA server configurations to ensure that per-node permissions are explicitly defined rather than relying solely on namespace-level default inheritance until the upgrade is completed.
- Identify all instances of the `node-opcua` package within the environment and verify the version against the vulnerable range (2.42.0 <= version < 2.180.0).
