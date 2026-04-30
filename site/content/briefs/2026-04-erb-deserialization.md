---
title: ERB Deserialization Bypass via def_module/def_method/def_class
slug: 2026-04-erb-deserialization
description: A deserialization vulnerability exists in Ruby ERB versions before 4.0.3.1, version 4.0.4, ERB versions 5.0.0 before 6.0.1.1, and ERB versions 6.0.2 before 6.0.4. The `@_init` instance variable guard in `ERB#result` and `ERB#run` can be bypassed via `ERB#def_module`, `ERB#def_method`, and `ERB#def_class`, allowing arbitrary code execution when an ERB object is reconstructed via `Marshal.load` on untrusted data.
date: "2026-04-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - deserialization
  - rce
  - ruby
  - rails
vendors:
  - RubyGems
products:
  - ERB
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-41316
    cvss: 8.1
references:
  - https://github.com/advisories/GHSA-q339-8rmv-2mhv
rules:
  - title: Detect ERB def_module Code Execution via Deserialization
    description: Detects code execution via ERB's def_module during deserialization, exploiting the @_init guard bypass.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1213
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Marshal.load with ActiveSupport::Deprecation
    description: Detects potentially malicious deserialization of ActiveSupport::Deprecation objects, which may indicate exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1555
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Ruby versions before ERB 2.2.0 implemented an `@_init` instance variable guard in `ERB#result` and `ERB#run` to prevent code execution upon deserialization via `Marshal.load`. This guard is intended to block execution when an ERB object is reconstructed from untrusted data. However, the methods `ERB#def_method`, `ERB#def_module`, and `ERB#def_class` were not given the same protection, creating a bypass. An attacker capable of triggering `Marshal.load` on untrusted data in a Ruby application with the `erb` gem loaded can exploit `ERB#def_module` (using its zero-argument, default-parameter form) as a code execution sink. This bypass impacts Ruby on Rails applications that import untrusted serialized data, Ruby tools employing `Marshal.load` for caching or IPC, and legacy Rails applications (pre-7.0) utilizing Marshal for cookie session serialization. This bypass renders the `@_init` mitigation ineffective across all ERB versions from 2.2.0 through 6.0.3. Combined with the DeprecatedInstanceVariableProxy gadget (present in all ActiveSupport versions through 7.2.3), this enables a universal RCE gadget chain for Ruby 3.2+ applications using Rails. The vulnerability is identified as CVE-2026-41316.

## Attack Chain

1. The attacker crafts a malicious Ruby object containing an `ERB` instance and/or an `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy` instance.
2. The `ERB` instance has its `@src` instance variable set to a string containing malicious code with the "end\nsystem('id')\ndef x" payload.
3. The vulnerable application calls `Marshal.load` on the crafted object, triggering deserialization.
4. During deserialization, the `DeprecatedInstanceVariableProxy` is instantiated (if used), which then invokes the `ERB#def_module` method via `method_missing`.
5. The `ERB#def_module` method calls `ERB#def_method` without checking the `@_init` guard.
6. Inside `ERB#def_method`, the malicious code in `@src` is wrapped in a method definition and evaluated via `module_eval`.
7. The "end\nsystem('id')\ndef x" payload causes the `system('id')` command to execute during the `module_eval` call, bypassing the intended deserialization protection.
8. The attacker achieves arbitrary code execution on the target system, gaining the ability to perform malicious actions.

## Impact

Successful exploitation allows an attacker to execute arbitrary code on the target system. This affects Ruby applications, including Ruby on Rails, which use `Marshal.load` on untrusted data. Specific impact includes potential compromise of web servers and the ability to read sensitive files, modify data, or install malware. Vulnerable applications include those using `Marshal.load` for caching, data import, or IPC, and legacy Rails applications (pre-7.0) using Marshal for cookie session serialization. This bypass renders the @_init mitigation ineffective across all ERB versions from 2.2.0 through 6.0.3.

## Recommendation

*   Upgrade your erb gem to version 4.0.3.1, 4.0.4.1, 6.0.1.1, or 6.0.4 to patch the vulnerability as described in the "Patches" section.
*   Avoid using `Marshal.load` on untrusted data, as it is inherently unsafe. Consider using alternative serialization formats like JSON or YAML.
*   Deploy the "Detect ERB def_module Code Execution via Deserialization" Sigma rule to detect exploitation attempts.
