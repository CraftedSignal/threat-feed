---
title: protobuf.js Code Injection Vulnerability in pbjs Static Output
slug: 2026-05-protobufjs-code-injection
description: Code injection vulnerability exists in protobuf.js (protobufjs-cli) due to insufficient sanitization of schema-controlled names during static code generation using `pbjs`, allowing attacker-controlled code injection into the generated JavaScript output.
date: "2026-05-12T15:07:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - protobufjs
  - pbjs
vendors:
  - npm
products:
  - protobufjs-cli (<= 1.2.0)
  - protobufjs-cli (>= 2.0.0, <= 2.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-6r35-46g8-jcw9
  - CVE-2026-44295
rules:
  - title: Detect CVE-2026-44295 Exploitation Attempt — pbjs Code Generation with Suspicious Schema Names
    description: Detects attempts to exploit CVE-2026-44295 by identifying calls to pbjs with command-line arguments containing potentially malicious characters in schema names during static code generation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - process_creation
      - linux
  - title: Detect CVE-2026-44295 Exploitation Attempt — pbjs Code Generation with Suspicious Schema Names (Windows)
    description: Detects attempts to exploit CVE-2026-44295 by identifying calls to pbjs with command-line arguments containing potentially malicious characters in schema names during static code generation on Windows.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A code injection vulnerability exists within the protobuf.js library, specifically affecting the `pbjs` static code generation tool. This vulnerability arises from insufficient sanitization of schema-controlled names during the process of generating static JavaScript code. When a crafted schema or JSON descriptor, influenced by a malicious actor, is used as input for `pbjs`, it can lead to the injection of attacker-controlled code into the resulting JavaScript output. This injected code is then executed if the generated file is later executed or imported by an application or build process. This vulnerability impacts applications that use `pbjs` to generate static code from potentially untrusted schemas. Affected versions include protobufjs-cli versions 1.2.0 and earlier, as well as versions 2.0.0 up to and including 2.0.1.

## Attack Chain

1. An attacker crafts a malicious protobuf schema or JSON descriptor.
2. The attacker includes specially crafted schema names (e.g., namespace, enum, service names) designed to inject JavaScript code.
3. The attacker provides the malicious schema to an application or build process that uses `pbjs` for static code generation.
4. `pbjs` processes the malicious schema, incorporating the attacker's code into the generated JavaScript output due to insufficient sanitization.
5. The application or build process imports or executes the generated JavaScript file.
6. The injected JavaScript code is executed within the context of the application or build process.
7. The attacker gains control over the application's execution flow.
8. The attacker achieves arbitrary code execution, potentially leading to data exfiltration or system compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker to inject and execute arbitrary code within an application that uses `protobufjs-cli` to generate static JavaScript code from untrusted schemas. The consequences of this code execution could range from data theft and denial of service to complete system compromise. This impacts applications and build processes that rely on `pbjs` to handle protobuf schemas provided or influenced by external entities, and can potentially affect any system where this generated JavaScript code is later executed.

## Recommendation

- Do not run affected versions of `pbjs` static code generation on untrusted schemas or descriptors, as mentioned in the advisory.
- If untrusted schemas must be accepted, validate schema names before code generation and run generation in an isolated environment, as recommended in the advisory.
- Upgrade to a patched version of `protobufjs-cli` that addresses CVE-2026-44295.
