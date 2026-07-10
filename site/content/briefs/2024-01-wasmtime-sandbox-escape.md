---
title: Wasmtime Cranelift AArch64 Sandbox Escape Vulnerability
slug: 2024-01-wasmtime-sandbox-escape
description: A critical sandbox escape vulnerability exists in Wasmtime's Cranelift compilation backend on aarch64, allowing guest WebAssembly modules to bypass bounds checks and achieve arbitrary read/write access to host memory under specific configuration conditions.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wasmtime
  - cranelift
  - aarch64
  - sandbox-escape
  - memory-corruption
vendors:
  - Wasmtime
products:
  - Wasmtime
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-jhxm-h53p-jm7w
rules:
  - title: Detect Wasmtime process with disabled spectre mitigations
    description: Detects Wasmtime processes running with disabled Spectre mitigations, a condition required for exploiting the Cranelift AArch64 sandbox escape vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - process_creation
      - linux
  - title: Detect Wasmtime process memory access outside expected regions
    description: Detects Wasmtime processes performing memory accesses outside of expected memory regions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - process_memory
      - linux
rules_count: 2
---

A critical vulnerability has been identified in Wasmtime's Cranelift compilation backend specifically affecting aarch64 architectures. This flaw stems from a miscompilation of heap accesses, leading to incorrect address calculations within guest WebAssembly modules. This allows a malicious guest module to bypass memory bounds checks and gain unauthorized read/write access to the host system's memory. The vulnerability is present in Wasmtime versions prior to 36.0.7, between 37.0.0 and 42.0.2, and version 43.0.0. Successful exploitation requires specific conditions: 64-bit WebAssembly linear memories must be in use (`Config::wasm_memory64` enabled, which is the default), and either Spectre mitigations or signals-based-traps must be disabled. This vulnerability allows a sandbox escape enabling attackers to compromise the host system from within the WebAssembly runtime.

## Attack Chain

1. A malicious WebAssembly module is loaded into Wasmtime.
2. The module is compiled using the Cranelift backend on an aarch64 architecture.
3. The module contains a heap access operation of the form `load(iadd(base, ishl(index, amt)))` where `amt` is a constant.
4. Cranelift miscompiles this load instruction due to an incorrect mask applied to the `amt` value during instruction selection.
5. The WebAssembly module performs a bounds check on the intended memory address.
6. Due to the miscompilation, the address used for the actual load operation is different from the address used in the bounds check, effectively bypassing the check.
7. The module performs an arbitrary read or write operation to host memory outside of the WebAssembly sandbox.
8. The attacker gains control or extracts sensitive information from the host system.

## Impact

Successful exploitation of this vulnerability allows a malicious WebAssembly module to escape the Wasmtime sandbox. This grants the attacker the ability to read and write arbitrary memory locations on the host system, leading to potential data exfiltration, privilege escalation, or complete system compromise. The vulnerability affects applications and systems that rely on Wasmtime for sandboxed execution of WebAssembly code on aarch64 architectures, potentially impacting a wide range of services and infrastructure.

## Recommendation

*   Upgrade to Wasmtime version 36.0.7, 42.0.2, or 43.0.1 or later to patch the vulnerability as described in the [Wasmtime advisory](https://github.com/advisories/GHSA-jhxm-h53p-jm7w).
*   If upgrading is not immediately feasible, ensure that Spectre mitigations are enabled in your Wasmtime configuration as a workaround.
*   As an alternative workaround, disable `Config::wasm_memory64` if your application does not require 64-bit WebAssembly linear memories.
*   Monitor systems running Wasmtime on aarch64 architectures for anomalous memory access patterns that could indicate exploitation of this vulnerability.
