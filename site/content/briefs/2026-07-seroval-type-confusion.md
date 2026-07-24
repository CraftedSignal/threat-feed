---
title: Seroval Type Confusion Vulnerability in fromJSON() Leads to Deserialization RCE
slug: 2026-07-seroval-type-confusion
description: A critical type confusion vulnerability, CVE-2026-59940, in `seroval.fromJSON()` versions prior to 1.5.3 allows attackers to provide malicious JSON input that misleads Promise control nodes into operating on attacker-controlled values, potentially leading to arbitrary method invocation and remote code execution or server compromise in downstream server frameworks like TanStack Start that deserialize untrusted input with plugins enabled.
date: "2026-07-24T16:23:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - type-confusion
  - deserialization
  - rce
  - npm
  - ghsa
vendors:
  - TanStack
products:
  - seroval (versions prior to 1.5.3)
  - TanStack Start
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: In applications that deserialize untrusted Seroval JSON with plugins enabled, this could allow attacker-controlled deserialization side effects.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: this primitive could become unintended server-side invocation and, depending on exposed application functionality, remote code execution or equivalent server compromise.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mv8w-475r-vwqw
---

A critical type confusion vulnerability, identified as CVE-2026-59940, exists in the `seroval` JavaScript serialization library, specifically within the `seroval.fromJSON()` function, affecting all versions prior to 1.5.3. This flaw allows an attacker to craft special JSON input that exploits a logic error where internal Promise resolver records are confused with attacker-controlled values during deserialization. When applications, particularly downstream server frameworks such as TanStack Start, deserialize untrusted Seroval JSON with plugins enabled, this type confusion can lead to the invocation of attacker-controlled methods or callable wrappers. This primitive could enable unintended server-side invocation, potentially resulting in remote code execution (RCE) or equivalent server compromise, depending on the application's exposed functionality. The issue was privately coordinated and fixed in `seroval@1.5.3`.

## Attack Chain

1. **Craft Malicious JSON**: An attacker crafts a specially designed Seroval JSON payload. This payload contains values that, due to the type confusion vulnerability (CVE-2026-59940), are engineered to be misinterpreted by `seroval.fromJSON()` as internal Promise resolver records.
2. **Deliver Payload**: The attacker sends this malicious Seroval JSON input to a vulnerable server-side application that uses `seroval.fromJSON()` for deserialization of untrusted client input.
3. **Initiate Deserialization**: The vulnerable application receives the untrusted JSON and passes it to `seroval.fromJSON()` for processing. This typically occurs when plugins are enabled in the Seroval configuration.
4. **Trigger Type Confusion**: During the deserialization, `seroval.fromJSON()` attempts to process Promise control nodes. Due to the type confusion flaw, it fails to properly verify the type of values from the general deserialization reference table, mistakenly treating attacker-controlled data as legitimate Promise resolver records.
5. **Invoke Attacker-Controlled Methods**: This misinterpretation leads to the Promise control nodes operating on these attacker-controlled values, causing the unintended invocation of methods or callable wrappers that were defined through registered plugins in the downstream framework.
6. **Achieve Server Compromise**: Depending on the specific methods invoked and the functionality exposed by the application's plugins, this arbitrary method invocation can lead to severe consequences, including remote code execution (RCE), arbitrary file manipulation, or other forms of server compromise.

## Impact

The vulnerable deserialization path can confuse attacker-created values with internal Seroval promise resolver records, leading to a deserialization side-effect primitive when untrusted JSON is processed with plugins enabled. The direct impact on applications using `seroval` is the ability for an attacker to influence program flow during deserialization. In downstream server frameworks, such as TanStack Start, which might register plugins returning callable wrappers, this vulnerability can be leveraged to trigger unintended server-side invocations. This can escalate to remote code execution (RCE), arbitrary file system access, or full server compromise, depending on the scope of the invoked methods. The vulnerability was privately validated against TanStack Start, confirming potential downstream exploitation.

## Recommendation

* Upgrade the `seroval` package to version `1.5.3` or later immediately to mitigate CVE-2026-59940.
* For downstream projects accepting Seroval JSON from untrusted clients, implement defense-in-depth controls such as restricting accepted Seroval node types for client-to-server payloads.
* Restrictively allowlist plugin tags for inbound deserialization processes to prevent unintended plugin activation.
* Avoid registering plugins that produce callable or privileged values for untrusted inputs unless absolutely necessary.
* Implement regression tests to ensure deserialization cannot cause unintended server-side invocation as a side effect.
