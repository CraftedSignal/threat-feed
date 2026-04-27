---
title: FlowiseAI AirtableAgent Remote Code Execution via Prompt Injection
slug: 2024-01-flowise-rce
description: A remote code execution vulnerability exists in FlowiseAI's AirtableAgent.ts due to insufficient input verification when using Pandas, allowing attackers to inject malicious code into the prompt and execute arbitrary code via Pyodide.
date: "2026-04-16T21:43:57Z"
severities:
  - critical
tags:
  - flowiseai
  - rce
  - prompt-injection
  - airtable
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-f228-chmx-v6j6
rules:
  - title: Detect FlowiseAI AirtableAgent Prompt Injection
    description: Detects potential prompt injection attempts targeting the FlowiseAI AirtableAgent by looking for suspicious keywords in HTTP request parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Python Code Execution via Pyodide in FlowiseAI
    description: Detects execution of Python code via Pyodide within FlowiseAI, potentially indicating successful prompt injection and code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

FlowiseAI is susceptible to a remote code execution (RCE) vulnerability within the AirtableAgent function. This function, designed to retrieve and process datasets from Airtable.com, is flawed due to the lack of input sanitization. Specifically, user-supplied input is directly incorporated into a prompt template, which is then used to generate Python code executed by Pyodide. By injecting malicious payloads into the prompt, an attacker can bypass the intended behavior of the language model and…
