---
title: BentoML SSTI via Unsandboxed Jinja2 in Dockerfile Generation
slug: 2024-02-bentoml-ssti
description: BentoML versions 1.4.37 and earlier are vulnerable to server-side template injection (SSTI), where the Dockerfile generation function uses an unsandboxed jinja2.Environment allowing arbitrary Python code execution on the host machine when a malicious bento archive is imported and containerized, bypassing container isolation and potentially granting full access to the host filesystem and environment variables.
date: "2026-04-03T23:14:15Z"
severities:
  - critical
tags:
  - ssti
  - bentoml
  - code-execution
  - docker
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://github.com/advisories/GHSA-v959-cwq9-7hr6
rules:
  - title: Detect BentoML SSTI Payload in Dockerfile Template
    description: Detects potential Server-Side Template Injection (SSTI) payloads in Dockerfile templates, specifically targeting BentoML's use of Jinja2.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Process Execution from BentoML
    description: Detects suspicious process execution originating from the BentoML process, which may indicate exploitation of the SSTI vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

BentoML versions 1.4.37 and earlier contain a critical vulnerability related to server-side template injection (SSTI). The vulnerability stems from the use of an unsandboxed Jinja2 environment within the `generate_containerfile()` function, which is responsible for creating Dockerfiles. By crafting a malicious bento archive containing a specially crafted `dockerfile_template`, an attacker can inject arbitrary Python code that executes directly on the host machine when a victim imports and…
