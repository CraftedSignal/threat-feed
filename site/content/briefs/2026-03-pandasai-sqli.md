---
title: SQL Injection Vulnerability in Sinaptik AI PandasAI lancedb Extension
slug: 2026-03-pandasai-sqli
description: A SQL injection vulnerability exists in Sinaptik AI PandasAI up to version 0.1.4 within the pandasai-lancedb Extension, allowing remote exploitation through manipulation of multiple functions in the lancedb.py file.
date: "2026-03-28T12:16:04Z"
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - pandasai
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4996
rules:
  - title: Detect Potential PandasAI SQL Injection Attempts
    description: Detects potential SQL injection attempts targeting PandasAI applications based on suspicious characters in URI queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Malicious SQL Commands in HTTP Requests
    description: This rule identifies HTTP requests containing potentially malicious SQL commands, indicating possible SQL injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in Sinaptik AI PandasAI versions up to 0.1.4. This vulnerability resides within the pandasai-lancedb Extension, specifically affecting the `delete_question_and_answers`, `delete_docs`, `update_question_answer`, `update_docs`, `get_relevant_question_answers_by_id`, and `get_relevant_docs_by_id` functions within the `lancedb.py` file. The vulnerability allows for remote exploitation, potentially enabling attackers to execute arbitrary SQL queries…
