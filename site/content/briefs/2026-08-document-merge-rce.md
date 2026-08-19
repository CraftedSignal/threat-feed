---
title: Remote Code Execution in document-merge-service via Jinja2 SSTI
slug: 2026-08-document-merge-rce
description: The Adfinis document-merge-service is vulnerable to RCE via server-side template injection (SSTI) in XLSX templates due to an improperly sandboxed Jinja2 environment.
date: "2026-08-19T22:34:11Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Adfinis
products:
  - document-merge-service
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Adfinis document-merge-service is vulnerable to remote code execution (RCE) via server-side template injection (SSTI) when processing XLSX templates.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The vulnerability arises because the xltpl library utilizes a non-sandboxed Jinja2 environment, allowing an attacker to execute arbitrary code within the service container's context.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w47q-945m-q9pc
  - https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade document-merge-service to v9.1.0 to address CVE-2026-53964
      owner: IT Operations
      due: 24h
      evidence: Source advisory confirms patch in v9.1.0.
  mitigation_plan:
    - priority: immediate
      action: Disable XLSX template processing in document-merge-service
      owner: IT Operations
      addresses: CVE-2026-53964
      evidence: Source recommends disabling XLSX templates as a workaround.
---

The Adfinis document-merge-service is vulnerable to remote code execution (RCE) via server-side template injection (SSTI) affecting versions prior to 9.1.0. The vulnerability, tracked as CVE-2026-53964, exists in the way the application processes XLSX templates using the xltpl library. Because the underlying Jinja2 environment is not properly sandboxed, an attacker can supply malicious template content that, when processed, executes arbitrary code. The code runs with the privileges of the document-merge-server user (UID 901) within the container, granting the attacker significant control over the application environment. Defenders should prioritize updating to version 9.1.0 or disabling XLSX template processing to mitigate this risk.

## Impact

Successful exploitation leads to full remote code execution in the context of the service container. This allows attackers to compromise the application, potentially access sensitive data within the environment, and perform lateral movement or persistence within the containerized infrastructure.

## Recommendation

* Update the document-merge-service package to version 9.1.0 or later to patch CVE-2026-53964.
* As an immediate workaround, disable the upload and processing of XLSX templates within the document-merge-service configuration until the patch is applied.
* Implement strict input validation on all file uploads to ensure only expected file formats and content types are accepted.
