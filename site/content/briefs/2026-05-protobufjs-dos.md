---
title: protobufjs Denial of Service via Unsafe Option Paths (CVE-2026-44290)
slug: 2026-05-protobufjs-dos
description: protobufjs is vulnerable to a denial of service (CVE-2026-44290). Crafted protobuf schemas or JSON descriptors can cause option handling to write to properties on global JavaScript constructors, corrupting process-wide built-in functionality. An attacker who can control protobuf schemas or JSON descriptors may be able to corrupt built-in process state, resulting in a persistent denial of service.
date: "2026-05-12T15:03:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - protobufjs
  - CVE-2026-44290
vendors:
  - npm
products:
  - protobufjs (<= 7.5.5)
  - protobufjs (>= 8.0.0, <= 8.0.1)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-jvwf-75h9-cwgg
  - CVE-2026-44290
rules:
  - title: Detect CVE-2026-44290 Exploitation Attempt - Suspicious Root.load Usage
    description: Detects CVE-2026-44290 exploitation attempt — suspicious calls to Root.load with potentially malicious schema names
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - process_creation
      - linux
  - title: Detect CVE-2026-44290 Exploitation Attempt - Suspicious Root.fromJSON Usage
    description: Detects CVE-2026-44290 exploitation attempt — suspicious calls to Root.fromJSON with potentially malicious schema names
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

protobufjs is vulnerable to a denial-of-service (DoS) vulnerability (CVE-2026-44290) due to unsafe handling of schema option paths. This flaw allows specially crafted protobuf schemas or JSON descriptors to manipulate properties on global JavaScript constructors during option processing. This can lead to corruption of process-wide built-in functionality, potentially causing subsequent application or protobufjs code to fail. The vulnerability affects applications that parse or load protobuf schemas or descriptors from untrusted sources, specifically protobufjs versions up to 7.5.5 and versions 8.0.0 through 8.0.1. Exploitation requires the attacker to control the content of a protobuf schema or descriptor. This issue does not allow code execution.

## Attack Chain

1. An attacker crafts a malicious protobuf schema or JSON descriptor.
2. The crafted schema contains option paths designed to traverse inherited object properties.
3. The application parses the malicious schema using protobufjs reflection APIs (e.g., `parse`, `Root.load`, `Root.loadSync`, or `Root.fromJSON`).
4. During option processing, protobufjs attempts to write to properties on global JavaScript constructors based on the attacker-controlled option paths.
5. The write operation corrupts the state of global JavaScript constructors.
6. Subsequent application code relying on the corrupted constructors will fail or behave unpredictably.
7. Further protobufjs operations may also fail due to the corrupted environment.
8. This results in a persistent denial of service for the lifetime of the affected process.

## Impact

Successful exploitation leads to a persistent denial-of-service condition, as the corrupted JavaScript constructors will cause application failures throughout the lifetime of the affected process. This vulnerability primarily affects applications that handle protobuf schemas or descriptors from untrusted sources. Affected protobufjs versions include those up to 7.5.5 and versions 8.0.0 through 8.0.1. The impact is limited to denial of service.

## Recommendation

- Upgrade to a patched version of protobufjs (later than 7.5.5 or later than 8.0.1) to remediate CVE-2026-44290.
- Avoid parsing or loading protobuf schemas or JSON descriptors from untrusted sources as a general security practice.
- If untrusted schemas must be accepted, validate or reject option names containing unsafe property path components before loading them.
- Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect attempts to exploit CVE-2026-44290.
