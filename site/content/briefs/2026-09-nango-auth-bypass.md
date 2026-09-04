---
title: Authentication Bypass in Nango Runner tRPC Server
slug: 2026-09-nango-auth-bypass
description: Nango versions prior to 0.71.6 contain an authentication bypass vulnerability allowing unauthenticated attackers to achieve remote code execution via the tRPC runner server.
date: "2026-09-04T19:26:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nango:nango:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - nango
vendors:
  - Nango
products:
  - Nango (< 0.71.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Nango before 0.71.6 contains a missing authentication vulnerability in the runner tRPC server that allows unauthenticated attackers to execute arbitrary JavaScript code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: Attacker... execute arbitrary JavaScript code by invoking the exposed start procedure without credentials.
    confidence_band: high
cves:
  - id: CVE-2026-9317
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9317
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Nango to version 0.71.6 or later
      owner: IT Operations
      due: 24h
      evidence: Nango before 0.71.6 contains a missing authentication vulnerability
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the runner tRPC port via firewall
      owner: IT Operations
      addresses: CVE-2026-9317
      evidence: Attackers with network access to the runner port can send requests to the unauthenticated start procedure
---

Nango versions prior to 0.71.6 are vulnerable to an authentication bypass in the runner tRPC server. An unauthenticated attacker with network access to the runner service can invoke the exposed 'start' procedure without providing the required RUNNER_SECRET_KEY. This flaw allows the execution of arbitrary JavaScript code within the context of the runner process, leading to remote code execution (RCE). The vulnerability stems from a failure to enforce authentication controls on specific internal tRPC procedures, making it a critical risk for deployments where the runner is reachable by untrusted network entities. Defenders must upgrade to version 0.71.6 or later to enforce proper credential validation.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable runner ports associated with Nango deployments.
2. Attacker establishes a network connection to the target tRPC runner server port.
3. Attacker crafts a malicious tRPC request targeting the 'start' procedure.
4. Attacker omits or provides an invalid RUNNER_SECRET_KEY in the request payload.
5. The Nango runner server fails to validate the request, incorrectly assuming authorization.
6. The 'start' procedure processes the request and executes the embedded malicious JavaScript code.
7. Attacker achieves remote code execution within the runner process context.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript code on the Nango runner service. This can lead to full system compromise, unauthorized data access, and potential lateral movement within the network infrastructure where the runner is hosted.

## Recommendation

1. Upgrade Nango to version 0.71.6 or later immediately to patch CVE-2026-9317.
2. Restrict network access to the Nango runner tRPC server port to authorized management subnets only.
3. Implement egress filtering and monitoring to detect suspicious network activity originating from the Nango runner process.
