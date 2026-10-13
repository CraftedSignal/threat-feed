---
title: Unauthenticated Remote Code Execution in Xorbits Xoscar
slug: 2026-10-xorbits-xoscar-deserialization
description: Xorbits Xoscar versions 0.11.2 and earlier are vulnerable to unauthenticated remote code execution via insecure deserialization of data sent over the actor-pool TCP channel.
date: "2026-10-13T22:38:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:xorbits:xoscar:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - deserialization
  - vulnerability
  - cve-2026-49950
vendors:
  - Xorbits
products:
  - Xoscar (<= 0.11.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Xorbits Xoscar through 0.11.2 contains an unauthenticated deserialization vulnerability that allows remote attackers to execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-49950
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-49950
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Xoscar to a version later than 0.11.2
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-49950 remediation
  mitigation_plan:
    - priority: immediate
      action: Restrict access to Xoscar actor-pool TCP ports
      owner: IT Operations
      addresses: CVE-2026-49950
      evidence: Unauthenticated TCP channel exposure
---

Xorbits Xoscar versions up to and including 0.11.2 are susceptible to a critical unauthenticated deserialization vulnerability, tracked as CVE-2026-49950. The vulnerability exists within the application's actor-pool TCP communication channel. Remote, unauthenticated attackers can supply crafted malicious payloads that are processed by the SocketChannel.recv() function. This input is passed directly to the cloudpickle.loads() method without prior validation of the message type. Because this processing occurs before the application verifies the data structure, attackers can trigger the execution of arbitrary code via pickle __reduce__ gadgets. This attack results in remote code execution (RCE) with the privileges of the server process, which frequently runs as the root user on GPU-enabled nodes, potentially leading to full cluster compromise.

## Impact

Successful exploitation allows remote attackers to execute arbitrary code with root-level privileges on GPU nodes running Xoscar. This exposes the entire infrastructure to unauthorized access, data exfiltration, and potential persistence mechanisms within the targeted environment.

## Recommendation

- Upgrade Xorbits Xoscar to a patched version beyond 0.11.2 immediately to remediate CVE-2026-49950.
- Implement network segmentation to restrict access to the actor-pool TCP ports to only authorized compute nodes.
- Monitor network traffic for anomalous data structures or serialized Python objects being sent to the TCP channels used by the Xoscar actor-pool.
