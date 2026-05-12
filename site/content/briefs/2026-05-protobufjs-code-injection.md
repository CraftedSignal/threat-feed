---
title: protobuf.js Code Injection via Crafted Bytes Field Defaults (CVE-2026-44293)
slug: 2026-05-protobufjs-code-injection
description: protobuf.js is vulnerable to code injection (CVE-2026-44293); by crafting a protobuf descriptor with a non-string default value for a `bytes` field, an attacker can inject arbitrary Javascript code into the generated `toObject` conversion function if default values are enabled, requiring the application to load an attacker-controlled schema and convert a message of the affected type with defaults enabled.
date: "2026-05-12T15:07:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - protobufjs
  - CVE-2026-44293
  - javascript
products:
  - protobufjs
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-66ff-xgx4-vchm
  - https://www.cve.org/CVERecord?id=CVE-2026-44293
rules:
  - title: Detect CVE-2026-44293 Exploitation — Protobuf.js Code Injection
    description: Detects CVE-2026-44293 exploitation — Monitors for suspicious code execution patterns during protobuf processing, potentially indicating exploitation via a crafted `bytes` field default.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1592.002
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-44293 Exploitation — Protobuf.js Code Generation with Suspicious Bytes Default
    description: Detects CVE-2026-44293 exploitation — Monitors file modifications where a Protobuf schema is being written with 'bytes' field including suspicious Javascript code inside default value.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1592.002
    data_sources:
      - file_event
      - windows
rules_count: 2
---

protobuf.js versions 7.5.5 and earlier, and 8.0.0 through 8.0.1 are vulnerable to code injection (CVE-2026-44293). The vulnerability stems from the way protobuf.js generates JavaScript code for `toObject` conversion. A malicious actor can craft a protobuf descriptor that contains a `bytes` field with a default value that is not a string. When the `toObject` function is generated, this non-string default value is included as an unsafe expression, leading to the injection of attacker-controlled code into the generated function if default values are enabled. This poses a risk when applications load untrusted protobuf schemas or descriptors, allowing for arbitrary JavaScript execution within the application's context.

## Attack Chain

1. An attacker crafts a malicious protobuf descriptor. This descriptor includes a `bytes` field that has a non-string default value, such as JavaScript code.
2. The attacker delivers the malicious protobuf descriptor to a vulnerable application. This could be achieved by hosting the descriptor on a server or sending it directly to the application.
3. The application loads and parses the attacker-controlled protobuf descriptor, generating code using the protobuf.js library.
4. During code generation, protobuf.js incorporates the attacker-controlled, non-string default value into the `toObject` conversion function.
5. The application calls the `toObject` function with default values enabled for the affected type.
6. When the `toObject` function is executed, the injected JavaScript code from the malicious default value is executed within the application's process.
7. The attacker achieves arbitrary JavaScript execution within the context of the application.
8. The attacker may then leverage this code execution to perform unauthorized actions, such as accessing sensitive data or compromising the system.

## Impact

Successful exploitation of this vulnerability (CVE-2026-44293) allows an attacker to execute arbitrary JavaScript code within the context of a vulnerable application using protobuf.js. This could lead to sensitive data exposure, unauthorized access to system resources, or complete system compromise. The impact is especially severe if the application processes untrusted protobuf schemas.

## Recommendation

- Upgrade to protobuf.js version 8.0.2 or later to remediate the vulnerability.
- Avoid loading protobuf schemas or JSON descriptors from untrusted sources as described in the overview.
- Validate or restrict field options before loading schemas from untrusted sources, and run schema processing in an isolated environment as described in the workaround section.
- Deploy the Sigma rule "Detect CVE-2026-44293 Exploitation — Protobuf.js Code Injection" to identify potential exploitation attempts by monitoring for unexpected code execution during protobuf processing.
