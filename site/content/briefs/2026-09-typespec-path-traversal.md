---
title: Path Traversal in TypeSpec OpenAPI3 Emitter
slug: 2026-09-typespec-path-traversal
description: The @typespec/openapi3 emitter fails to sanitize version-derived path tokens, allowing arbitrary file creation or overwrite outside the intended output directory.
date: "2026-09-08T21:49:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - file-write
  - typespec
  - supply-chain
vendors:
  - TypeSpec
products:
  - compiler (<= 1.15.0)
  - openapi3 (<= 1.15.0)
  - http (<= 1.15.0)
  - versioning (<= 0.85.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The proof-of-concept demonstrates the vulnerability being invoked and executed via PowerShell scripts on a Windows-based host environment.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2q42-4q24-7rgv
action_plan:
  priority: elevated
  owners:
    - Development Teams
    - Security Operations
  immediate_actions:
    - action: Audit build pipelines for TypeSpec compiler execution environments to ensure they run with least-privilege service accounts.
      owner: Security Operations
      due: 48h
      evidence: The threat allows file overwrite based on the permissions of the compiler process.
  mitigation_plan:
    - priority: immediate
      action: Monitor for unexpected file write activity in build directories and ensure build environments are ephemeral.
      owner: DevOps
      addresses: File overwrite via TypeSpec compiler
      evidence: Path traversal allows writing files outside the intended output directory.
---

The `@typespec/openapi3` emitter package is vulnerable to a path traversal flaw caused by improper sanitization of user-controlled input. Specifically, the value of a `@versioned` enum member in a TypeSpec (`.tsp`) file is interpolated directly into the output filename template without checking for path traversal characters (`..`) or absolute path indicators. During the emission process, the TypeSpec compiler's `emitFile` function performs no validation to ensure the resolved path remains within the designated `emitterOutputDir`. 

An attacker capable of providing a malicious `.tsp` file to the compiler can force the application to write or overwrite files anywhere on the local filesystem that the compiler process has write access to. While the written content is constrained to valid OpenAPI YAML or JSON structures, the ability to overwrite configuration files or sensitive application data allows for potential denial-of-service or system instability. This vulnerability affects the TypeSpec compiler stack, specifically `openapi3` and `compiler` versions `1.15.0` and earlier.

## Attack Chain

1. Attacker crafts a malicious TypeSpec source file (`.tsp`) containing a `@versioned` enum member.
2. The attacker sets a version value containing directory traversal sequences, such as `../../../../tmp/target_file`.
3. The attacker invokes the TypeSpec compiler on the malicious source file.
4. The `openapi3` emitter reads the crafted version value during the serialization of the OpenAPI specification.
5. The compiler performs path interpolation using the malicious version string, constructing a path that points outside the `emitterOutputDir`.
6. The `emitFile` utility executes the file write operation using the resolved traversal path.
7. The target file on the host filesystem is overwritten with the generated OpenAPI YAML/JSON content.

## Impact

Successful exploitation allows for arbitrary file creation or overwrite, leading to file corruption and potential denial-of-service scenarios. The impact is limited to the compiler process's filesystem permissions and the file formats supported by the emitter, precluding direct remote code execution or unauthorized file disclosure in the documented exploitation path.

## Recommendation

Prioritize the implementation of path sanitization within the TypeSpec compiler emission pipeline.

- Implement logic in the `openapi3` emitter to resolve the absolute path of the output file after token interpolation and verify it resides within the `emitterOutputDir`.
- Slugify or strictly validate all filename tokens derived from spec attributes to strip path separators, absolute path prefixes, and traversal components.
- Audit and patch `packages/compiler/src/core/emitter-utils.ts` to enforce filesystem containment checks during the `writeFile` routine.
- Review all TypeSpec projects for usage of externally supplied or untrusted input in `@versioned` enum definitions.
