---
brief_id: brief-2026-10-22-wasmtime-stack-overflow
event_id: brief-2026-10-22-wasmtime-stack-overflow
revision: 1
activity_at: "2026-10-22T20:27:34Z"
title: 'Wasmtime: Stack buffer overflow in async callback handling (CVE-2026-115384)'
slug: 2026-10-wasmtime-stack-overflow
description: Wasmtime versions prior to 48.0.4 and 49.0.2 are vulnerable to a stack buffer overflow allowing sandbox escape or host crashes via unvalidated async callback result types.
date: "2026-10-22T20:27:34Z"
lastmod: "2026-10-22T20:28:46Z"
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
  validation_status: Source confirmed; no specific detection indicators or IOCs available.
cpes:
  - cpe:2.3:a:bytecodealliance:wasmtime:*:*:*:*:*:*:*:*
vendors:
  - Bytecode Alliance
products:
  - Wasmtime (39.0.0 - 48.0.3, 49.0.0 - 49.0.1)
  - Wasmtime (< 24.0.13, >= 25.0.0 < 36.0.14, >= 37.0.0 < 46.0.3, >= 47.0.0 < 47.0.4)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can supply components with mistyped component-model-async callback functions to overwrite return addresses, crashing the host or escaping the sandbox.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A guest with write access to any sandboxed directory can read and write any host-accessible file.
    confidence_band: high
cves:
  - id: CVE-2026-115384
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-115392
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115384
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115392
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Wasmtime to version 48.0.4 or 49.0.2 to remediate CVE-2026-115384
      owner: IT Operations
      due: 24h
      evidence: Source defines versions 48.0.4 and 49.0.2 as containing the fix.
  mitigation_plan:
    - priority: immediate
      action: Identify and inventory all services running vulnerable versions of Wasmtime
      owner: Security Operations
      addresses: CVE-2026-115384
      evidence: Affected products list.
updates:
  - at: "2026-10-22T20:28:46Z"
    level: L2
    summary: added coverage for Wasmtime (< 24.0.13, >= 25.0.0 < 36.0.14, >= 37.0.0 < 46.0.3, >= 47.0.0 < 47.0.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-115392
---

Wasmtime contains a stack buffer overflow vulnerability (CVE-2026-115384) in its component model implementation. Malicious guests can exploit improper validation of async callback result types to write approximately 16KB of data to the native stack. This allows for the overwriting of return addresses, which can lead to host process crashes or a full sandbox escape. The vulnerability affects Wasmtime versions 39.0.0 through 48.0.3 and 49.0.0 through 49.0.1.

## Impact
Successful exploitation may result in arbitrary code execution outside the WebAssembly sandbox, enabling an attacker to compromise the host system, or causing immediate termination of the host process (Denial of Service).

## Recommendation
- Upgrade Wasmtime to version 48.0.4 or 49.0.2 immediately.
- Audit WebAssembly components loaded into the environment to ensure they originate from trusted sources.
- If immediate patching is not possible, implement stricter runtime sandboxing or containerization around Wasmtime-powered services to limit the impact of a potential sandbox escape.
