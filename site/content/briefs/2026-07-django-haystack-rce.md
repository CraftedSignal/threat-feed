---
title: Remote Code Execution via eval() in django-haystack Elasticsearch Deserialization
slug: 2026-07-django-haystack-rce
description: A critical remote code execution (RCE) vulnerability in the Elasticsearch backend of django-haystack allows attackers to execute arbitrary Python commands by manipulating `SearchField` aliases and indexed content, leading to full compromise of the Django application.
date: "2026-07-15T22:43:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - python
  - django
  - elasticsearch
  - deserialization
  - supply-chain
vendors:
  - django-haystack
products:
  - django-haystack
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: If the value is an attacker-controlled Python expression such as `__import__('os').system(...)`, the expression is executed unconditionally.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: payload = f"__import__('os').system('echo PWNED_BY_EVAL_RCE > {MARKER_FILE}')"
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-r3hx-x5rh-p9vv
iocs:
  - type: file_path
    value: /tmp/django_haystack_eval_rce_proof
  - type: string
    value: PWNED_BY_EVAL_RCE
ioc_counts:
  file_path: 1
  string: 1
rules:
  - title: Detect django-haystack RCE Marker File Creation
    description: Detects the creation of a specific marker file `/tmp/django_haystack_eval_rce_proof` with content 'PWNED_BY_EVAL_RCE' via `os.system()` command execution, indicating successful exploitation of the django-haystack Elasticsearch backend RCE vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1059.006
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical remote code execution (RCE) vulnerability (CVSS 8.5 High) has been identified in the Elasticsearch backend of the `django-haystack` library. This flaw arises when a `SearchField` is configured with an `index_fieldname` alias that differs from the logical field name. During the processing of search results, the backend attempts to look up fields by their logical name, but the data is stored under the alias. This lookup failure causes the raw field value to be passed directly to `_to_python()` which subsequently calls `eval()` without proper type-safety checks. An attacker who can control content indexed into Elasticsearch, and then trigger a search that returns this malicious content, can inject arbitrary Python expressions such as `__import__('os').system(...)`. This allows for the execution of arbitrary Python and shell commands within the Django application process, potentially leading to full compromise of the server. This vulnerability affects all Django applications utilizing the Elasticsearch backend with `index_fieldname` aliasing, regardless of the application's authentication mechanisms.

## Attack Chain

1. An attacker gains control over content that is subsequently indexed into Elasticsearch by the vulnerable Django application.
2. The application's `SearchIndex` contains a `SearchField` declared with an `index_fieldname` (e.g., `"name_s"`) that differs from its logical attribute name (e.g., `"name"`).
3. The attacker-controlled data, specifically a crafted Python expression, is stored in Elasticsearch under the `index_fieldname` alias.
4. A search operation is performed, retrieving the malicious document from Elasticsearch, including the attacker-controlled `_source` data.
5. During result processing by `ElasticsearchSearchBackend._process_results()`, the backend attempts to map Elasticsearch fields to logical field names.
6. The lookup for the `index_fieldname` (e.g., `"name_s"`) fails because `index.fields` is keyed by logical names (e.g., `"name"`).
7. Due to the failed lookup, the raw, attacker-controlled value from Elasticsearch is passed to `_to_python(value)`.
8. The `_to_python()` function then unconditionally calls `eval(value)`, executing the attacker's injected Python expression with the privileges of the Django application.

## Impact

This vulnerability results in Remote Code Execution (RCE), allowing an attacker to execute arbitrary Python and shell commands on the affected server. Successful exploitation grants the attacker the same privileges as the running Django application, leading to a complete compromise of the server's confidentiality, integrity, and availability. The impact extends to all Django applications that use the `django-haystack` Elasticsearch backend and declare `SearchField` instances with `index_fieldname` aliases, irrespective of their authentication configurations. The severity is high, as demonstrated by the CVSS 3.1 Base Score of 8.5.

## Recommendation

* Patch the `django-haystack` library immediately to apply the provided fix that introduces `index.field_map` remapping and uses `ast.literal_eval` instead of `eval()`.
* Deploy the provided Sigma rule to your SIEM to detect the creation of the RCE marker file `/tmp/django_haystack_eval_rce_proof`.
* Enable process creation logging on Linux servers to ensure visibility into executed commands, which is required for the provided Sigma rule.
* Review all `SearchIndex` configurations within your Django applications to identify and assess any `SearchField` declarations using `index_fieldname` aliases, especially those handling user-controlled input.
