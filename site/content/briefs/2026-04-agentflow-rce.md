---
title: AgentFlow Arbitrary Code Execution via Pipeline Path Manipulation (CVE-2026-7466)
slug: 2026-04-agentflow-rce
description: AgentFlow is vulnerable to arbitrary code execution (CVE-2026-7466) by manipulating the `pipeline_path` parameter in POST requests to `/api/runs` and `/api/runs/validate`, allowing attackers to execute arbitrary Python code.
date: "2026-04-29T19:16:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-7466
  - rce
  - code-injection
vendors:
  - berabuddies
products:
  - AgentFlow
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
cves:
  - id: CVE-2026-7466
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7466
  - https://github.com/berabuddies/agentflow/pull/18
  - https://github.com/berabuddies/agentflow/pull/18/changes/7e61b6ce846b3d700456e4874394dc868905a9f2
  - https://www.vulncheck.com/advisories/agentflow-arbitrary-python-pipeline-execution-via-pipeline-path
rules:
  - title: Detect AgentFlow Suspicious Pipeline Path in POST Request
    description: Detects POST requests to AgentFlow endpoints with potentially malicious pipeline paths.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect AgentFlow Suspicious Pipeline Path in Validate Request
    description: Detects POST requests to AgentFlow validate endpoints with potentially malicious pipeline paths.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AgentFlow is susceptible to an arbitrary code execution vulnerability identified as CVE-2026-7466. This flaw stems from insufficient validation of the `pipeline_path` parameter within the `/api/runs` and `/api/runs/validate` endpoints. By crafting malicious POST requests and supplying a user-controlled `pipeline_path`, an attacker can induce the AgentFlow API to load and execute arbitrary Python pipeline files present on the server's filesystem. Successful exploitation leads to code execution within the security context of the user running AgentFlow, potentially granting the attacker full control over the affected system. This vulnerability poses a significant threat to organizations utilizing AgentFlow, as it can lead to data breaches, system compromise, and other malicious activities.

## Attack Chain

1.  Attacker identifies an AgentFlow instance running a vulnerable version.
2.  Attacker crafts a POST request to the `/api/runs` endpoint, including a `pipeline_path` parameter.
3.  The `pipeline_path` parameter is set to the path of a malicious Python file already existing on the AgentFlow server (or uploaded previously through other means).
4.  The attacker sends the malicious POST request to the `/api/runs` endpoint.
5.  AgentFlow processes the request without properly validating the `pipeline_path`.
6.  AgentFlow loads and executes the Python file specified in the `pipeline_path`.
7.  The attacker-controlled Python code executes with the privileges of the AgentFlow process.
8.  The attacker achieves arbitrary code execution, potentially leading to complete system compromise, data exfiltration, or denial of service.

## Impact

Successful exploitation of CVE-2026-7466 allows an attacker to execute arbitrary code on the AgentFlow server. This can lead to a complete compromise of the system, including the theft of sensitive data, modification of critical system files, or the installation of backdoors for persistent access. The severity of the impact depends on the privileges of the user account running AgentFlow, but in many cases, it can lead to full system administrator access.

## Recommendation

*   Implement input validation and sanitization on the `pipeline_path` parameter within the `/api/runs` and `/api/runs/validate` endpoints to prevent arbitrary file loading and execution.
*   Monitor web server logs for POST requests to `/api/runs` and `/api/runs/validate` containing suspicious `pipeline_path` values (see example Sigma rule below).
*   Restrict file system permissions to limit the ability of the AgentFlow user to read and execute arbitrary Python files.
*   Apply available patches or updates for AgentFlow as soon as they are released to address this vulnerability.
