---
title: Remote Code Execution in LMCache Multiprocess ZMQ Transport
slug: 2026-10-lmcache-rce
description: LMCache versions 0.3.9 through 0.5.5 are vulnerable to unauthenticated remote code execution due to insecure pickle deserialization within the multiprocess ZeroMQ transport layer.
date: "2026-10-16T22:28:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:lmcache:lmcache:*:*:*:*:*:*:*:*
tags:
  - rce
  - deserialization
  - multiprocess
  - zeromq
vendors:
  - LMCache
products:
  - LMCache (>= 0.3.9, < 0.5.6)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who can reach the transport port can send a single crafted message and execute arbitrary code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The transport binds to localhost, and single-process (in-process) mode does not open the port.
    confidence_band: high
cves:
  - id: CVE-2026-105192
    cvss: 9.8
    epss: 0.00482
references:
  - https://github.com/advisories/GHSA-w5f2-9q9c-ff4h
  - https://github.com/LMCache/LMCache/pull/5644
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Restrict network access to port 5555 via firewall
      owner: Security Engineering
      due: 24h
      evidence: Source workaround recommends restricting access to the transport port with firewall rules.
  mitigation_plan:
    - priority: immediate
      action: Upgrade LMCache to version 0.5.6
      owner: IT Operations
      addresses: CVE-2026-105192
      evidence: Fixed in 0.5.6
---

LMCache is vulnerable to unauthenticated remote code execution (RCE) via unsafe pickle deserialization in its multiprocess (distributed) mode transport. The vulnerability exists in the ZeroMQ ROUTER socket that LMCache opens to allow worker processes to register and share KV cache blocks. This socket lacks authentication mechanisms such as CURVE, ZAP, or password validation. By default, the transport binds to localhost, but it becomes remotely exploitable when operators bind it to routable network interfaces using the --host parameter.

An attacker can send a crafted msgpack-encoded message to the transport port (default 5555) containing a malicious pickle payload within a register request. This payload is deserialized via `pickle.loads` inside `DeviceIPCWrapper.Deserialize` before the application handler validates the input. The code executes with the privileges of the LMCache process, which, in official container images, runs as root. The vulnerability affects LMCache versions 0.3.9 through 0.5.5 and related release candidates.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable LMCache ZeroMQ transport ports (default 5555).
2. Attacker generates a malicious pickle object designed to execute arbitrary OS commands (e.g., `os.system`).
3. Attacker encodes the malicious payload using the `msgspec.msgpack` format, specifically targeting the extension code 1 used by `DeviceIPCWrapper`.
4. Attacker constructs a `REGISTER_KV_CACHE` message frame containing the malformed serialized object.
5. Attacker uses a ZMQ DEALER socket to send the multipart message to the target LMCache server.
6. The LMCache server receives the message and triggers the vulnerable `pickle.loads` function during the argument decoding phase.
7. The arbitrary command executes on the host with the permissions of the LMCache service process.
8. Attacker achieves persistent access, data exfiltration, or further lateral movement within the container or host environment.

## Impact

The vulnerability allows unauthenticated attackers to achieve full remote code execution on any LMCache node where the ZMQ transport is bound to a routable IP address. Official container images are documented to run the LMCache process as root, elevating the severity of the exploit to full system compromise. If the service is left on default localhost bindings, the impact is limited to local privilege escalation or container escape if reachable by other processes on the same host.

## Recommendation

- Upgrade to LMCache 0.5.6 or later, which replaces pickle with typed MessagePack descriptors and adds input validation.
- Apply firewall rules or network policies to restrict access to TCP port 5555, ensuring only trusted peer traffic is permitted.
- Reconfigure the LMCache deployment to bind the transport to localhost unless multi-node functionality is strictly required.
- Run the LMCache service as a non-privileged user rather than root to reduce the blast radius of potential compromises.
- Audit logs and network connections to port 5555 for any anomalies, as the server will log a type error after the malicious payload has already been executed.
