---
title: Wasmtime Winch Compiler Aarch64 Sandbox Escape Vulnerability
slug: 2026-04-wasmtime-sandbox-escape
description: A sandbox escape vulnerability exists in Wasmtime versions 25.0.0 to 36.0.7, 37.0.0 to 42.0.2, and version 43.0.0 when using the Winch compiler backend on aarch64 architecture, potentially allowing a Wasm guest to access host memory outside its sandbox, leading to denial of service, data leaks, or remote code execution.
date: "2026-04-11T12:00:00Z"
severities:
  - critical
tags:
  - wasmtime
  - sandbox-escape
  - memory-corruption
  - aarch64
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-34987
    epss: 0.00042
references:
  - https://github.com/advisories/GHSA-xx5w-cvp6-jv83
rules:
  - title: Detect Wasmtime Using Winch Compiler
    description: Detects when Wasmtime is executed with the non-default Winch compiler, which is required for the vulnerability to be exploitable.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    data_sources:
      - process_creation
      - linux
  - title: Detect Potential Wasmtime Sandbox Escape - Memory Access Violation
    description: Detects potential exploitation attempts by monitoring for memory access violations within the Wasmtime process that may indicate a sandbox escape.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Wasmtime, a WebAssembly runtime, is vulnerable to a sandbox escape issue when using the Winch compiler backend on aarch64 architecture. This vulnerability, affecting versions 25.0.0 through 36.0.7, 37.0.0 through 42.0.2, and 43.0.0, stems from improper handling of memory offsets within the Winch compiler. The Winch compiler is not the default, requiring the `-Ccompiler=winch` flag to activate it. A malicious or compromised Wasm guest could exploit this flaw to access host memory outside of its…
