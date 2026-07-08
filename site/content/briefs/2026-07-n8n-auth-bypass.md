---
title: CVE-2026-56776 - n8n Authorization Bypass via Workflow Test Run Endpoint
slug: 2026-07-n8n-auth-bypass
description: An authenticated user can exploit CVE-2026-56776, an authorization bypass vulnerability in n8n versions prior to 1.123.55, 2.25.7, and 2.26.2, by sending a POST request to the `/workflows/{workflowId}/test-runs/new` endpoint to trigger unauthorized workflow execution, leading to unintended outbound API calls, data mutations, and other side effects in connected downstream systems.
date: "2026-07-08T14:24:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - n8n
  - web-application
  - vulnerability
  - privilege-escalation
vendors:
  - n8n GmbH
products:
  - n8n
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated user with read-only access to a workflow can trigger a real evaluation test run, causing the workflow to execute via the internal workflow runner and resulting in unintended outbound API calls, data mutations, or other side effects in connected downstream systems.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: n8n before 1.123.55, 2.25.7, and 2.26.2 contains an authorization bypass in the POST /workflows/{workflowId}/test-runs/new endpoint, which authorizes access using the workflow:read scope instead of workflow:execute.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An authenticated user with read-only access to a workflow can trigger a real evaluation test run
    confidence_band: high
cves:
  - id: CVE-2026-56776
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56776
rules:
  - title: Detects CVE-2026-56776 Exploitation - n8n Authorization Bypass
    description: Detects CVE-2026-56776 exploitation - HTTP POST to /workflows/{workflowId}/test-runs/new endpoint indicating an attempt to bypass authorization and execute a workflow without proper permissions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The NVD has published details regarding CVE-2026-56776, an authorization bypass vulnerability affecting n8n workflow automation platform versions prior to 1.123.55, 2.25.7, and 2.26.2. This critical flaw allows an authenticated user, typically with `workflow:read` permissions, to trigger the execution of workflows that they are not authorized to run. The vulnerability lies within the `POST /workflows/{workflowId}/test-runs/new` API endpoint, which incorrectly validates authorization against `workflow:read` scope instead of `workflow:execute`. Exploitation results in unintended side effects, including outbound API calls, data mutations, and other actions within connected downstream systems, effectively elevating the attacker's privileges from read-only to full execution for a given workflow. This poses a significant risk to organizations using n8n with its Evaluations feature and RBAC, as it permits unauthorized data manipulation and external system interaction.

## Attack Chain

1. An attacker gains or already possesses valid credentials for an n8n instance, granting them authenticated access, specifically with `workflow:read` permissions to a target workflow.
2. The attacker identifies a specific workflow (`workflowId`) they wish to execute but for which they lack the `workflow:execute` permission.
3. The attacker crafts an HTTP POST request targeting the vulnerable endpoint: `/workflows/{workflowId}/test-runs/new`.
4. The attacker sends this POST request to the n8n application.
5. Due to an authorization bypass, the n8n application incorrectly validates the request using the `workflow:read` scope instead of the required `workflow:execute` scope.
6. The n8n internal workflow runner is triggered, initiating a real evaluation test run of the specified workflow, despite the user lacking explicit execution privileges.
7. The executed workflow performs its defined actions, which may include making unintended outbound API calls, modifying data in connected systems, or other unauthorized side effects.
8. The attacker has effectively escalated privileges and achieved unauthorized execution of a workflow.

## Impact

The successful exploitation of CVE-2026-56776 can lead to significant unauthorized actions within an organization's ecosystem. An authenticated user, despite having only read-level permissions, can trigger sensitive workflows designed for automation, potentially causing unintended outbound API calls, deletion or modification of critical data in connected downstream systems (e.g., CRM, ERP, databases), or the triggering of other business logic. While no specific victim counts are available, any organization utilizing n8n with RBAC project roles and the Evaluations feature, where `workflow:read` is granted without `workflow:execute`, is at risk of unauthorized data manipulation and privilege escalation.

## Recommendation

* Patch affected n8n instances immediately to versions 1.123.55, 2.25.7, 2.26.2 or later to remediate CVE-2026-56776.
* Deploy the provided Sigma rule "Detects CVE-2026-56776 Exploitation - n8n Authorization Bypass" to your SIEM and tune for your environment to identify attempts to exploit the `POST /workflows/{workflowId}/test-runs/new` endpoint.
* Review your n8n Role-Based Access Control (RBAC) configurations, especially for instances using the Evaluations feature, to ensure that users with `workflow:read` permissions cannot unintentionally trigger workflow executions.
* Ensure robust logging is enabled for your n8n web server to capture detailed HTTP request information (method, URI, and response status codes) which is critical for activating the detection rule.
