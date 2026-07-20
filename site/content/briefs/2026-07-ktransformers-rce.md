---
title: Critical Unauthenticated RCE in ktransformers (CVE-2026-63767)
slug: 2026-07-ktransformers-rce
description: A critical unauthenticated pickle deserialization vulnerability (CVE-2026-63767) in ktransformers versions up to 0.6.3 allows remote attackers to execute arbitrary commands by sending specially crafted pickle payloads containing malicious `__reduce__` methods to the SchedulerServer ZMQ ROUTER socket, leading to complete server compromise.
date: "2026-07-20T20:19:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - deserialization
  - remote-code-execution
  - python
  - zmq
  - vulnerability
vendors:
  - kvcache-ai
products:
  - ktransformers <= 0.6.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: ktransformers through 0.6.3... contains an unauthenticated pickle deserialization vulnerability that allows remote attackers to execute arbitrary commands by sending crafted pickle payloads to the SchedulerServer ZMQ ROUTER socket bound to all interfaces.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can exploit malicious __reduce__ methods embedded in crafted pickle payloads to execute arbitrary shell commands as the server process.
    confidence_band: high
cves:
  - id: CVE-2026-63767
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63767
  - https://github.com/kvcache-ai/ktransformers/commit/def0f9313d6e063b5c5ccdfa1f6707f7a40dfdca
  - https://github.com/kvcache-ai/ktransformers/issues/2087
  - https://github.com/kvcache-ai/ktransformers/pull/2091
  - https://www.vulncheck.com/advisories/ktransformers-unauthenticated-pickle-deserialization-rce-via-zmq
rules:
  - title: Detects CVE-2026-63767 Exploitation - Arbitrary Command Execution (Windows)
    description: Detects exploitation of CVE-2026-63767 by identifying suspicious child processes indicative of arbitrary command execution where the parent process is a Python interpreter, likely running ktransformers.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
      - T1059.004
      - T1059.006
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2026-63767 Exploitation - Arbitrary Command Execution (Linux)
    description: Detects exploitation of CVE-2026-63767 by identifying suspicious child processes indicative of arbitrary command execution where the parent process is a Python interpreter, likely running ktransformers.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1059.006
      - T1105
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical remote code execution (RCE) vulnerability, CVE-2026-63767, has been discovered in `ktransformers` versions through 0.6.3. This vulnerability stems from an unauthenticated pickle deserialization flaw that affects the `SchedulerServer ZMQ ROUTER` socket when it is bound to all interfaces. Remote attackers can exploit this by crafting and transmitting malicious pickle payloads directly to the exposed ZMQ socket. The payloads leverage Python's `__reduce__` methods to embed and execute arbitrary shell commands on the system hosting `ktransformers`. This allows attackers to gain full control over the affected server, potentially leading to data exfiltration, system integrity loss, or further network lateral movement. The vulnerability was fixed in commit `def0f93` and has a CVSS v3.1 base score of 9.8 (Critical).

## Attack Chain

1. An attacker identifies an internet-exposed `ktransformers` `SchedulerServer ZMQ ROUTER` socket on a vulnerable server running `ktransformers` version 0.6.3 or earlier.
2. The attacker crafts a Python pickle payload specifically designed to contain malicious `__reduce__` methods.
3. The malicious `__reduce__` methods are configured to invoke arbitrary system commands, such as spawning a shell or downloading additional malware.
4. The crafted pickle payload is transmitted unauthenticated over the network to the vulnerable `ZMQ ROUTER` socket.
5. The `ktransformers` application receives the untrusted pickle payload and initiates the deserialization process.
6. During deserialization, the Python `pickle` module processes the malicious `__reduce__` method, triggering the execution of the embedded arbitrary commands.
7. The arbitrary shell commands are executed on the underlying system with the privileges of the `ktransformers` server process, achieving remote code execution and initial system compromise.

## Impact

Successful exploitation of CVE-2026-63767 results in unauthenticated remote code execution on the server running `ktransformers`. This critical impact means attackers can fully compromise the affected system, leading to arbitrary data modification or deletion, sensitive data exfiltration, and the ability to establish persistence or pivot to other systems within the network. Depending on the server's role and data stored, this could lead to significant operational disruption, reputational damage, and regulatory penalties. The high CVSS score of 9.8 reflects the severity of this vulnerability.

## Recommendation

* Immediately apply the patch associated with commit `def0f93` or upgrade `ktransformers` to a version past 0.6.3, as referenced in the NVD.
* Deploy the provided Sigma rules for Windows and Linux to your SIEM to detect suspicious process creation activities originating from `python.exe` or other `ktransformers` related processes.
* Review network firewall rules to restrict direct external access to `ZMQ ROUTER` sockets, allowing connections only from trusted internal sources if possible.
* Monitor process creation logs (e.g., Sysmon on Windows, Auditd/Procfs on Linux) for unusual child processes spawned by Python interpreters or the `ktransformers` application.
