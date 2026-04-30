---
title: n8n Python Task Runner Sandbox Escape Vulnerability
slug: 2026-04-n8n-python-sandbox-escape
description: A sandbox escape vulnerability exists in n8n's Python Task Runner that allows an authenticated user with workflow creation/modification permissions to achieve arbitrary code execution on the task runner container, impacting n8n instances with the Python Task Runner enabled; upgrade to versions 1.123.32, 2.17.4, 2.18.1 or later to remediate the vulnerability.
date: "2026-04-29T21:21:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sandbox-escape
  - code-execution
  - vulnerability
vendors:
  - n8n
products:
  - n8n
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-44v6-jhgm-p3m4
rules:
  - title: Detect Suspicious Process Execution from n8n Task Runner
    description: Detects suspicious process execution originating from the n8n task runner container, indicating a potential sandbox escape.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Detect n8n Workflow Creation with Python Code Node
    description: Detects the creation or modification of n8n workflows that include a Python Code Node, which could be an early indicator of exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A sandbox escape vulnerability has been identified in the Python Task Runner of n8n, a workflow automation platform. This vulnerability, assigned CVE-2026-42234, allows an authenticated user who has permissions to create or modify workflows that contain a Python Code Node to escape the sandbox environment. Successful exploitation leads to arbitrary code execution within the task runner container. This issue specifically impacts n8n instances where the Python Task Runner is enabled. The vulnerability affects n8n versions prior to 1.123.32, versions between 2.17.0 and 2.17.4, and versions between 2.18.0 and 2.18.1. Defenders should prioritize patching their n8n instances or implementing available workarounds.

## Attack Chain

1. An attacker gains authenticated access to an n8n instance.
2. The attacker verifies the Python Task Runner is enabled.
3. The attacker creates or modifies an n8n workflow.
4. The workflow includes a Python Code Node.
5. The attacker crafts malicious Python code designed to escape the sandbox. This code could leverage vulnerabilities in the sandbox implementation to execute commands outside of the intended restricted environment.
6. The attacker triggers the workflow execution.
7. The malicious Python code executes, successfully escaping the sandbox.
8. Arbitrary code is executed on the task runner container, potentially leading to compromise of the n8n instance or the underlying infrastructure.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code within the n8n task runner container. This can lead to a full compromise of the n8n instance, allowing the attacker to steal sensitive data, disrupt services, or pivot to other systems within the network. While the exact number of affected instances is unknown, any n8n deployment with the Python Task Runner enabled and vulnerable versions are at risk.

## Recommendation

- Upgrade n8n to versions 1.123.32, 2.17.4, 2.18.1 or later to remediate the vulnerability as recommended by the vendor.
- If upgrading is not immediately possible, limit workflow creation and editing permissions to fully trusted users only, as mentioned in the advisory.
- As a temporary measure, disable the Python Code node by adding `n8n-nodes-base.code` to the `NODES_EXCLUDE` environment variable, or disable the Python Task Runner entirely as documented in the advisory.
- Monitor container execution for unexpected processes spawned from the n8n task runner container using the "Detect Suspicious Process Execution from n8n Task Runner" Sigma rule.
