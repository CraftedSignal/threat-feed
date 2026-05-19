---
title: Dasel Denial-of-Service Vulnerability via Unterminated Regex
slug: 2026-05-dasel-dos
description: Dasel versions 3.0.0 to 3.3.1 are vulnerable to a denial-of-service attack (CVE-2026-46378) where the selector lexer enters a non-terminating loop when tokenizing an unterminated regex pattern, causing 100% CPU usage on one core, which can be triggered by an attacker-controlled selector/query string.
date: "2026-05-19T20:11:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - dasel
  - CVE-2026-46378
vendors:
  - TomWright
products:
  - dasel
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-m6xr-fvfg-5g64
rules:
  - title: Detect Dasel Excessive CPU Consumption
    description: Detects a dasel process consuming a high percentage of CPU, which could indicate a denial-of-service attack related to CVE-2026-46378.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Dasel Unterminated Regex Input
    description: Detects commands invoking dasel with an unterminated regex pattern `r/` as input which may lead to CVE-2026-46378 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Dasel, a utility for selecting and modifying data structures, is susceptible to a denial-of-service vulnerability (CVE-2026-46378). This flaw resides in the selector lexer component of dasel versions 3.0.0 to 3.3.1. Specifically, the lexer enters an infinite loop when attempting to tokenize an unterminated regular expression pattern, such as `r/`. This causes a single CPU core to reach 100% utilization, effectively halting the processing of any further requests or operations relying on dasel. The vulnerability was confirmed on versions v3.3.1 (fba653c7f248aff10f2b89fca93929b64707dfc8) and on the master commit 0dd6132e0c58edbd9b1a5f7ffd00dfab1e6085ad, as well as v3.0.0. An attacker who can control or influence the selector/query string passed to dasel can exploit this, potentially leading to service disruption. No fix is currently available.

## Attack Chain

1. An attacker crafts a malicious input string containing an unterminated regular expression pattern (e.g., `r/`).
2. The attacker injects this malicious input into an application that uses dasel to process data. This injection point could be a web application, a command-line tool, or any other context where dasel is used to handle user-provided selectors.
3. The dasel application receives the malicious input and passes it to the `NewTokenizer` function in `selector/lexer/tokenize.go`.
4. The tokenizer begins to parse the input string and encounters the `r/` sequence.
5. The `parseCurRune` function invokes the `matchRegexPattern` closure.
6. Due to the missing closing `/`, the loop on line 243 of `tokenize.go` continues indefinitely, consuming CPU resources.
7. The affected process becomes unresponsive, leading to a denial-of-service condition.
8. The application relying on dasel functionality becomes unavailable or experiences degraded performance.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition. The affected process will consume 100% CPU on one core, rendering it unable to perform other tasks. This can impact web applications, command-line tools, and other systems that rely on dasel for data querying and modification. The severity depends on the criticality of the affected service, potentially disrupting business operations. While the proof of concept only affects one CPU core, in a containerized environment, this could trigger health checks to fail and the container to restart repeatedly.

## Recommendation

*   Apply a patch to dasel as soon as one becomes available from the vendor. This is the most effective way to mitigate the vulnerability.
*   Implement input validation on selector strings before they are passed to dasel. Specifically, reject any selector strings that start with `r/` and do not contain a closing `/`.
*   Deploy the Sigma rule provided to detect instances where a `dasel` process consumes excessive CPU, indicating a potential denial-of-service attack targeting this vulnerability.
*   Monitor dasel processes for unusually high CPU utilization, which can be an indicator of this vulnerability being exploited.
