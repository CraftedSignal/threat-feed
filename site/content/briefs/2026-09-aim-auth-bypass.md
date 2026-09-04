---
title: Authentication Bypass in Aim Remote Tracking Server
slug: 2026-09-aim-auth-bypass
description: The Aim remote tracking server version 3.29.1 contains an authentication bypass vulnerability allowing unauthenticated attackers to execute arbitrary methods and perform unauthorized data access or deletion.
date: "2026-09-04T15:26:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:aim:aim:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - cve-2026-85663
vendors:
  - Aim
products:
  - Aim (3.29.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can register clients, instantiate Repo resources, and invoke arbitrary methods to read experiments or delete runs.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The server fails to validate requests, allowing unauthenticated attackers to leverage the getattr function without an allowlist to invoke arbitrary methods.
    confidence_band: high
cves:
  - id: CVE-2026-85663
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85663
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the Aim tracking server to trusted CIDR blocks
      owner: IT Operations
      due: 24h
      evidence: Unauthenticated remote attackers can register clients and invoke arbitrary methods
  hunt_leads:
    - lead: Unauthorized client registration or Repo resource instantiation on Aim servers
      technique_id: T1190
      data_needed:
        - Web server logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Unauthenticated attackers can register clients, instantiate Repo resources
  mitigation_plan:
    - priority: immediate
      action: Isolate affected Aim 3.29.1 instances from the public internet
      owner: IT Operations
      addresses: CVE-2026-85663
      evidence: 'CVSS v3.1 Base Score: 9.8'
---

The Aim remote tracking server, specifically version 3.29.1, is affected by an authentication bypass vulnerability. The server fails to validate client requests and improperly dispatches arbitrary methods using the getattr function without an enforced allowlist. This flaw allows unauthenticated remote attackers to register new clients, instantiate Repo resources, and invoke unauthorized methods directly against the tracking server. Successful exploitation allows an attacker to manipulate sensitive experiment data, including reading private experiment logs or deleting recorded execution runs, potentially resulting in data loss or unauthorized exfiltration of model development telemetry. Defenders should prioritize restricting access to the Aim tracking server interface and monitoring for unauthorized API calls.

## Impact

Successful exploitation of CVE-2026-85663 allows unauthenticated remote actors to gain control over the tracking server's resources. This can lead to the complete loss of experiment integrity, the unauthorized deletion of training runs, and the leakage of metadata related to machine learning projects.

## Recommendation

- Restrict network access to the Aim tracking server instance to authorized internal networks only.
- Monitor web logs for unexpected POST requests directed at the Aim tracking server API endpoints that do not originate from known, authorized client IP addresses.
- Upgrade to a version of Aim that enforces server-side authentication and request validation once the vendor releases a patch.
