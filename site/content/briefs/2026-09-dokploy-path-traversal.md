---
title: Path Traversal Vulnerability in Dokploy
slug: 2026-09-dokploy-path-traversal
description: Dokploy versions up to 0.29.7 are vulnerable to remote path traversal via the writeTraefikConfigInPath function, allowing attackers to access arbitrary files on the system.
date: "2026-09-01T01:01:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:dokploy:dokploy:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - path-traversal
  - cve-2026-82954
vendors:
  - Dokploy
products:
  - Dokploy (<= 0.29.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument path results in path traversal. The attack can be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-82954
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82954
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the Dokploy management interface
      owner: IT Operations
      due: 24h
      evidence: Critical severity vulnerability accessible remotely
  mitigation_plan:
    - priority: immediate
      action: Isolate affected Dokploy instances from untrusted network segments
      owner: IT Operations
      addresses: CVE-2026-82954
      evidence: Unpatched path traversal vulnerability
  gaps:
    - Lack of vendor patch necessitates reliance on compensating network controls
---

Dokploy versions 0.29.7 and earlier contain a critical path traversal vulnerability (CVE-2026-82954) located within the `writeTraefikConfigInPath` function in `packages/server/src/utils/traefik/application.ts`. The flaw allows remote, unauthenticated attackers to manipulate the 'path' argument, leading to arbitrary file system access. This vulnerability permits the reading or overwriting of sensitive configuration files, which can be leveraged to gain unauthorized system control. The vulnerability is publicly disclosed, and given the nature of the software as a deployment management tool, successful exploitation carries a high risk of systemic compromise. The vendor has not provided a response or a patch as of the time of disclosure.

## Impact

The vulnerability carries a CVSS v3.1 base score of 9.9, reflecting its critical potential for unauthorized file access and system-level impact. Attackers targeting this vulnerability can extract sensitive environment variables, credentials, or Traefik configuration files, potentially escalating access to any containerized workloads managed by the Dokploy instance.

## Recommendation

- Monitor web application logs for suspicious path traversal patterns (e.g., directory indexing characters like "../") directed at Dokploy management endpoints.
- Apply network segmentation to ensure Dokploy management interfaces are not exposed to the public internet until a security patch is released by the vendor.
- Conduct an audit of the file system integrity in the Dokploy server environment to identify signs of unauthorized file modification or exfiltration.
