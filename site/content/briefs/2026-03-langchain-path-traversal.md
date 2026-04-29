---
title: LangChain Core Path Traversal Vulnerability in Legacy APIs
slug: 2026-03-langchain-path-traversal
description: A path traversal vulnerability in LangChain Core's legacy `load_prompt` functions allows attackers to read arbitrary files by injecting malicious paths into prompt configurations.
date: "2026-03-28T10:00:00Z"
type: coverage
types:
  - coverage
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

Multiple path traversal vulnerabilities have been identified within the `langchain-core` package, specifically affecting the legacy `load_prompt`, `load_prompt_from_config`, and `.save()` methods. These vulnerabilities stem from a lack of validation on file paths embedded within deserialized configuration dictionaries. An attacker who can influence or control the prompt configuration supplied to these functions can exploit this flaw to read arbitrary files on the host filesystem. The scope is constrained by file extension checks, limiting readable files to `.txt` for templates and `.json` or `.yaml` for examples. This issue impacts applications that accept prompt configurations from untrusted sources, such as low-code AI builders and API wrappers exposing `load_prompt_from_config()`. The vulnerable code resides within `langchain_core/prompts/loading.py` in the `_load_template()`, `_load_examples()`, and `_load_few_shot_prompt()` functions. This vulnerability is resolved in `langchain-core` version 1.2.22, and the affected functions are now deprecated.

## Attack Chain

1.  Attacker identifies an application using the vulnerable `langchain-core` library and the legacy `load_prompt_from_config()` function.
2.  Attacker crafts a malicious prompt configuration dictionary containing a `template_path`, `suffix_path`, `prefix_path`, `examples`, or `example_prompt_path` key with a path traversal sequence (e.g., `../../etc/passwd`) or an absolute path (e.g., `/etc/passwd`).
3.  The attacker injects the malicious configuration into the application, potentially via a low-code AI builder or an API endpoint that accepts prompt configurations.
4.  The application deserializes the malicious configuration dictionary and passes it to `load_prompt_from_config()`.
5.  `load_prompt_from_config()` calls the relevant vulnerable function (`_load_template()`, `_load_examples()`, or `_load_few_shot_prompt()`) based on the configuration.
6.  The vulnerable function reads the file specified in the malicious path without proper validation.
7.  The contents of the file are then incorporated into a prompt object.
8.  The application, believing the prompt is benign, processes it further, potentially disclosing the file contents to the attacker via an error message, logging, or other output channels.

## Impact

Successful exploitation allows an attacker to read arbitrary files on the system, potentially exposing sensitive information. This includes cloud-mounted secrets (e.g., `/mnt/secrets/api_key.txt`), configuration files (e.g., `requirements.txt`), cloud credentials (e.g., `~/.docker/config.json`), Kubernetes manifests, CI/CD configurations, and application settings. The impact is especially severe in applications that handle sensitive data or operate in cloud environments. While no victim numbers are available, any application using the vulnerable `langchain-core` versions is at risk.

## Recommendation

*   Upgrade `langchain-core` to version 1.2.22 or later to patch CVE-2026-34070.
*   Migrate away from the deprecated `load_prompt`, `load_prompt_from_config`, and `.save()` methods in favor of the `dumpd`/`dumps`/`load`/`loads` serialization APIs in `langchain_core.load`.
*   If you cannot immediately upgrade, sanitize user-supplied prompt configurations to prevent path traversal by rejecting absolute paths and paths containing `..` sequences.
*   Deploy the Sigma rule "LangChain Path Traversal Attempt" to detect attempts to exploit this vulnerability by monitoring process creations involving `python` and path traversal sequences in command line arguments.
