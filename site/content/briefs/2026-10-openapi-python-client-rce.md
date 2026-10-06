---
title: Arbitrary Code Generation in openapi-python-client
slug: 2026-10-openapi-python-client-rce
description: The openapi-python-client library is vulnerable to arbitrary code generation when processing malicious OpenAPI documents, leading to remote code execution upon importing the generated client.
date: "2026-10-06T18:48:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openapi-python-client_project:openapi-python-client:*:*:*:*:*:python:*:*
tags:
  - supply-chain
  - code-execution
  - python
products:
  - openapi-python-client (< 0.29.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Python'
    evidence: A malicious OpenAPI document processed by any openapi-python-client prior to 0.29.1 can generate arbitrary Python code.
    confidence_band: high
cves:
  - id: CVE-2026-105801
references:
  - https://github.com/advisories/GHSA-5293-mq8x-g3xj
action_plan:
  priority: elevated
  owners:
    - Development Teams
    - Security Operations
  immediate_actions:
    - action: Upgrade openapi-python-client to 0.29.1 or later
      owner: Development Teams
      due: 24h
      evidence: Versions starting with 0.29.1 have updated with guardrails to prevent arbitrary code generation.
  mitigation_plan:
    - priority: immediate
      action: Audit codebases for generated clients from untrusted OpenAPI documents
      owner: Security Operations
      addresses: CVE-2026-105801
      evidence: Carefully verify any existing generated code from untrusted documents.
---

The openapi-python-client library (versions prior to 0.29.1) contains a vulnerability identified as CVE-2026-105801. An attacker can craft a malicious OpenAPI document that, when processed by the library, results in the injection and generation of arbitrary Python code within the output. This vulnerability poses a significant risk to the software supply chain, as developers unknowingly import and execute this generated code within their own environments. The impact is direct arbitrary code execution upon the import of the generated client module. Defenders and developers should prioritize updating the library to version 0.29.1 or later. Furthermore, organizations should conduct a retroactive audit of all client code generated from untrusted or third-party OpenAPI documents to identify potential backdoors or malicious modifications.

## Impact

Successful exploitation allows for arbitrary code execution in the context of the user or system running the generated Python client. This affects any application utilizing openapi-python-client for automation of API client generation, particularly those integrating untrusted external schemas. If malicious code is generated and embedded in a production codebase, it could lead to full system compromise or data exfiltration.

## Recommendation

- Upgrade the openapi-python-client dependency to version 0.29.1 or higher immediately across all development and build environments.
- Audit existing projects for client code generated via openapi-python-client prior to the patch, specifically searching for unauthorized file system access, network connections, or unexpected subprocess invocations.
- Implement a policy to only process OpenAPI documents from verified, trusted sources for automated client generation.
