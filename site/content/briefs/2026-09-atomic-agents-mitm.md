---
title: Arbitrary Code Execution in atomic-agents-stack via MCP Registry Injection
slug: 2026-09-atomic-agents-mitm
description: The atomic-agents-stack library before 1.1.0 allows man-in-the-middle attackers to inject malicious subprocess commands by exploiting cleartext HTTP communication in the MCP server-registry backend.
date: "2026-09-15T17:44:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:atomic-agents:atomic-agents-stack:*:*:*:*:*:*:*:*
vendors:
  - atomic-agents
products:
  - atomic-agents-stack (< 1.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1557.001
    technique_name: Adversary-in-the-Middle
    evidence: An attacker can exploit this to intercept and rewrite catalog responses
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: injecting malicious commands and arguments that are subsequently executed as local subprocesses
    confidence_band: high
cves:
  - id: CVE-2026-91988
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91988
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade atomic-agents-stack to version 1.1.0
      owner: IT Operations
      due: 24h
      evidence: Source states versions before 1.1.0 are affected
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 1.1.0 or later
      owner: IT Operations
      addresses: CVE-2026-91988
      evidence: NVD vulnerability entry
---

The atomic-agents-stack library (prior to version 1.1.0) contains a vulnerability in its HTTP MCP server-registry backend factory that allows for the acceptance of unencrypted HTTP traffic. An attacker positioned to perform a man-in-the-middle (MITM) attack can intercept network traffic between the client and the registry service. By rewriting the catalog response, the attacker can supply arbitrary command and argument values. These injected parameters are subsequently processed by the MCPClientPool, which spawns them as local subprocesses. This flaw results in arbitrary code execution on the host machine running the agent, posing a significant risk to environments that rely on this library for agent-based automation and orchestration. Defenders should prioritize updating to version 1.1.0 or later to enforce secure communication and input validation for registry responses.

## Impact

Successful exploitation allows for remote code execution on any host running a vulnerable version of the atomic-agents-stack library. If compromised, an attacker gains the privileges of the service account executing the agent, potentially leading to unauthorized data access, lateral movement within the environment, or full system takeover.

## Recommendation

- Upgrade the atomic-agents-stack dependency to version 1.1.0 or later immediately.
- Implement network-level egress filtering and enforce TLS for all registry communication to prevent MITM interception.
- Audit logs for unexpected subprocesses spawned by the process hosting the atomic-agents-stack library.
