---
title: LangChain Core Path Traversal Vulnerability in Legacy APIs
slug: 2026-03-langchain-path-traversal
description: A path traversal vulnerability in LangChain Core's legacy `load_prompt` functions allows attackers to read arbitrary files by injecting malicious paths into prompt configurations.
date: "2026-03-28T10:00:00Z"
severities:
  - high
tags:
  - langchain
  - path-traversal
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1584
    technique_name: Compromise Software Supply Chain
references:
  - https://github.com/advisories/GHSA-qh6h-p6c9-ff54
rules:
  - title: LangChain Path Traversal Attempt
    description: Detects potential path traversal attempts in LangChain applications by monitoring process creations with 'python' and path traversal sequences in the command line.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1584
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Multiple path traversal vulnerabilities have been identified within the `langchain-core` package, specifically affecting the legacy `load_prompt`, `load_prompt_from_config`, and `.save()` methods. These vulnerabilities stem from a lack of validation on file paths embedded within deserialized configuration dictionaries. An attacker who can influence or control the prompt configuration supplied to these functions can exploit this flaw to read arbitrary files on the host filesystem. The scope is…
