---
title: OpenClaw Node Forgery via Missing Provenance Check (CVE-2026-53816)
slug: 2026-07-openclaw-node-forgery
description: A vulnerability, CVE-2026-53816, in npm/openclaw versions prior to 2026.5.18, allows a malicious or compromised paired node to forge 'exec' lifecycle events and send them to the gateway, which, due to a missing provenance check, accepts the attacker-supplied event data as legitimate execution results, leading to unauthorized capability exposure for the compromised node.
date: "2026-07-03T11:58:42Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openclaw:openclaw:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - privilege-escalation
  - server-side
  - npm
vendors:
  - OpenClaw
products:
  - npm/openclaw (< 2026.5.18)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: a malicious or compromised paired node could make the gateway treat attacker-supplied event data as an exec lifecycle result. In the vulnerable flow, that could steer the target session into an exec-event path that exposed capabilities the reduced node surface should not have provided.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036.005
    technique_name: 'Masquerading: Match Legitimate Name or Location'
    evidence: a paired node could send an exec lifecycle event that was accepted without enough provenance tying it to an authorized `system.run` request.
    confidence_band: high
cves:
  - id: CVE-2026-53816
    cvss: 7.2
    epss: 0.00342
references:
  - https://github.com/advisories/GHSA-3c6j-hq33-3jv4
  - CVE-2026-53816
---

A critical vulnerability, tracked as CVE-2026-53816, has been identified in the npm/openclaw package, affecting all versions prior to `2026.5.18`. This flaw allows an attacker who has already gained control of a paired OpenClaw node to bypass security checks and forge `exec` lifecycle events. OpenClaw nodes typically send these lifecycle events to a central gateway. However, due to an insufficient provenance check in affected versions, the gateway accepts these forged events as legitimate execution results. This deception can lead the target session to process attacker-controlled data, exposing capabilities that the compromised node should not possess. This issue primarily impacts deployments where nodes can send crafted `node.event` messages to the gateway and the target agent/session processes exec lifecycle events.

## Attack Chain

1.  An attacker gains control over an already paired OpenClaw node within the targeted environment.
2.  The compromised paired node crafts a malicious `node.event` message containing forged `exec` lifecycle event data.
3.  The forged event data is designed to mimic a legitimate `system.run` request or other authorized execution.
4.  The compromised node sends this crafted `node.event` message to the OpenClaw gateway.
5.  Due to a missing provenance check, the OpenClaw gateway accepts the forged `exec` lifecycle event without validating its origin or authorization.
6.  The gateway processes the attacker-supplied event data as if it were a legitimate execution result from an authorized `system.run` request.
7.  This process steers the target session into an exec-event path, exposing unauthorized capabilities to the compromised node.
8.  The attacker achieves privilege escalation or unauthorized control over functionality that the node's reduced surface should not have provided.

## Impact

The successful exploitation of CVE-2026-53816 enables a malicious or compromised OpenClaw node to gain unauthorized capabilities on the OpenClaw gateway and associated target sessions. By making the gateway treat attacker-supplied event data as legitimate execution results, the vulnerability effectively elevates the privileges of the compromised node beyond its intended scope. While it does not allow an unauthenticated caller to directly reach the gateway, it poses a significant threat in environments where an OpenClaw node has already been breached, potentially leading to broader system compromise and unauthorized data access or manipulation. Organizations with affected versions are at risk if any of their paired nodes are compromised.

## Recommendation

*   Upgrade to `openclaw@2026.5.18` or later immediately to patch CVE-2026-53816.
*   Ensure that all paired OpenClaw nodes originate from trusted and secured environments.
*   Implement a process to remove and re-pair any OpenClaw nodes that are suspected of being compromised.
