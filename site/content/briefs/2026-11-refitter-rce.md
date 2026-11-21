---
brief_id: brief-2026-11-21-refitter-rce
event_id: brief-2026-11-21-refitter-rce
revision: 1
activity_at: "2026-11-21T09:47:23Z"
title: 'Refitter: Arbitrary Code Execution via Crafted OpenAPI Specifications'
slug: 2026-11-refitter-rce
description: Multiple vulnerabilities in the Refitter .NET tool allow for arbitrary code execution during application startup via crafted OpenAPI specifications that exploit unescaped attribute string emission.
date: "2026-11-21T09:47:23Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "1"
  rating: C1
  likelihood: likely
cpes:
  - cpe:2.3:a:christianhelle:refitter:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=B462E146-953F-5BAF-9974-FC55A56AA045&utm_source=rss&utm_medium=rss
tags:
  - rce
  - openapi
  - dotnet
  - supply-chain
vendors:
  - christianhelle
products:
  - refitter
affected_os:
  - linux
  - macos
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A [ModuleInitializer] method in that class executes attacker code when the generated assembly is loaded at application startup.
cves:
  - id: CVE-2026-63344
    epss: 0.0035
    kev_status: "false"
  - id: CVE-2026-63345
    epss: 0.0035
    kev_status: "false"
  - id: CVE-2026-63346
    epss: 0.0035
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2026-63344
  - https://cveawg.mitre.org/api/cve/CVE-2026-63345
  - https://cveawg.mitre.org/api/cve/CVE-2026-63346
  - https://sploitus.com/exploit?id=B462E146-953F-5BAF-9974-FC55A56AA045&utm_source=rss&utm_medium=rss
  - https://github.com/christianhelle/refitter/commit/63a19b03699a9c267d6fab5f758ec26484db83a1
action_plan:
  hunt_leads:
    - lead: Identify suspicious .NET assemblies containing 'file class' declarations with [ModuleInitializer] attributes that perform unexpected file system operations (such as creating files in /tmp/lab/) or execute unauthorized commands. Focus on identifying applications generated or updated using the Refitter tool and inspect the generated 'Client.cs' source code for breakout payloads in [Header(...)] attributes.
      technique_id: T1059
      data_needed:
        - File system logs for unexpected file creation
        - Source code audit of generated Refit client files
        - Process execution logs for .NET application startup events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: A crafted name survives Refitter's default OpenAPI validation and, starting from a PARAMETER-LIST position, closes the parameters + method + interface + namespace, injects a top-level file class with a [ModuleInitializer] method... .NET runs [ModuleInitializer] methods at assembly load, so the attacker's code executes at application startup.
---

## Overview
Refitter is a tool for generating a C# REST API client using the Refit library. Vulnerabilities (CVE-2026-63344, CVE-2026-63345, CVE-2026-63346) exist in versions prior to 2.1.2, where input from an OpenAPI specification is emitted verbatim into C# attribute strings without proper escaping. An attacker-influenced OpenAPI description can break out of the intended attribute context to inject a top-level `file class` containing a `[ModuleInitializer]` method. This method executes attacker code when the generated assembly is loaded at application startup, even if the generated client is never called.

## Attack Chain
1. An attacker provides a crafted OpenAPI specification (e.g., specific content-type keys, paths, or header parameter names) to the Refitter tool.
2. Refitter processes the input and emits the crafted strings verbatim into generated Refit attributes.
3. The breakout allows the injection of arbitrary code via `[ModuleInitializer]` into the generated C# assembly.
4. When a victim application compiles and loads the generated assembly at startup, the .NET runtime triggers the injected code.

## Impact
Successful exploitation results in arbitrary code execution in the context of the application that compiles and loads the generated assembly.

## Recommendation
Upgrade to Refitter version 2.1.2 or later to ensure proper escaping of attribute strings.
