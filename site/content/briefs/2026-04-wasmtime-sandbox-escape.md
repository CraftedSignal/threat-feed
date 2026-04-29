---
title: Wasmtime Winch Compiler Aarch64 Sandbox Escape Vulnerability
slug: 2026-04-wasmtime-sandbox-escape
description: A sandbox escape vulnerability exists in Wasmtime versions 25.0.0 to 36.0.7, 37.0.0 to 42.0.2, and version 43.0.0 when using the Winch compiler backend on aarch64 architecture, potentially allowing a Wasm guest to access host memory outside its sandbox, leading to denial of service, data leaks, or remote code execution.
date: "2026-04-11T12:00:00Z"
type: coverage
types:
  - coverage
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

Wasmtime, a WebAssembly runtime, is vulnerable to a sandbox escape issue when using the Winch compiler backend on aarch64 architecture. This vulnerability, affecting versions 25.0.0 through 36.0.7, 37.0.0 through 42.0.2, and 43.0.0, stems from improper handling of memory offsets within the Winch compiler. The Winch compiler is not the default, requiring the `-Ccompiler=winch` flag to activate it. A malicious or compromised Wasm guest could exploit this flaw to access host memory outside of its designated linear memory region. Successful exploitation could lead to denial of service, sensitive data leaks from the host process, or, with write access, potentially arbitrary remote code execution on the host system. Defenders should prioritize patching or switching to the Cranelift compiler backend to mitigate this critical vulnerability.

## Attack Chain

1.  An attacker crafts a malicious WebAssembly module specifically designed to exploit the memory offset vulnerability in the Winch compiler.
2.  The attacker deploys the malicious Wasm module to a system running a vulnerable version of Wasmtime using the Winch compiler backend (`-Ccompiler=winch`).
3.  The vulnerable Wasmtime instance loads and compiles the malicious Wasm module using the Winch compiler.
4.  Due to the flawed memory offset calculation within Winch, the Wasm module is able to access memory addresses outside of its allocated linear memory region.
5.  The Wasm module reads sensitive data from the host process's memory space, such as configuration files, API keys, or other confidential information.
6.  Alternatively, the Wasm module attempts to write arbitrary data to the host process's memory space, potentially overwriting critical system data or injecting malicious code.
7.  Successful memory corruption leads to a denial-of-service condition, a data leak, or potentially arbitrary code execution within the context of the host process.
8.  The attacker leverages the compromised host process to further compromise the system or network.

## Impact

Successful exploitation of this vulnerability allows a malicious Wasm guest to escape its sandbox and access the host system's memory. This can result in a denial of service, where the host process crashes due to memory corruption. More critically, it can lead to the exfiltration of sensitive data from the host process, potentially exposing confidential information. In the worst-case scenario, the attacker could achieve arbitrary code execution on the host system, leading to a complete system compromise. The number of potential victims is dependent on the adoption rate of Wasmtime with the Winch compiler enabled in production environments, but given the severity of the potential impact, any vulnerable instance represents a significant risk.

## Recommendation

*   Upgrade to Wasmtime version 43.0.1, 42.0.2, or 36.0.7 to patch CVE-2026-34987.
*   If upgrading is not immediately feasible, switch to the Cranelift compiler backend by removing the `-Ccompiler=winch` flag from the Wasmtime execution command.
*   Monitor Wasmtime deployments for unexpected crashes or memory access violations that may indicate exploitation attempts. While no specific IOCs are provided, unusual process behavior from Wasmtime should be investigated.
