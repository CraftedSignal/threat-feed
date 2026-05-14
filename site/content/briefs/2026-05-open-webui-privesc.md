---
title: Open WebUI Missing Authorization on Tool Update Endpoint Allows Privilege Escalation to Code Execution
slug: 2026-05-open-webui-privesc
description: Open WebUI is vulnerable to privilege escalation and code execution because a missing authorization check on the tool update endpoint allows a user with write access to a tool to replace the tool's server-side Python content and trigger execution, bypassing the intended `workspace.tools` security boundary.
date: "2026-05-14T20:37:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - code-execution
  - authorization
vendors:
  - Open WebUI
products:
  - Open WebUI
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.006
    technique_name: 'Command and Scripting Interpreter: Python'
references:
  - https://github.com/advisories/GHSA-p4fx-23fq-jfg6
rules:
  - title: Detect Open WebUI Tool Update Endpoint Bypass
    description: Detects attempts to exploit the Open WebUI privilege escalation vulnerability (GHSA-p4fx-23fq-jfg6) by monitoring POST requests to the tool update endpoint without proper authorization.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1205
    data_sources:
      - webserver
  - title: Detect Python Code Execution in Open WebUI Tool Updates
    description: Detects potential code execution attempts in Open WebUI tool updates by identifying suspicious keywords and functions in the content being updated.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI's tool update endpoint (`POST /api/v1/tools/id/{id}/update`) lacks the `workspace.tools` permission check that is enforced on the tool creation endpoint. This flaw permits a user, explicitly denied tool management permissions, to replace a tool's server-side Python code and execute it. The vulnerability breaks the intended security policy where `workspace.tools` is the trust boundary for code execution. A `write` access grant on a single tool is sufficient to bypass `workspace.tools` entirely, leading to code execution by an untrusted user. This vulnerability exists in the `main` branch of the Open WebUI project.

## Attack Chain

1. An administrator deploys Open WebUI with the default configuration.
2. The administrator enables `workspace.tools` permission for a trusted user, Alice.
3. Alice creates a tool with benign Python code.
4. Alice grants `write` access to the tool to an untrusted user, Bob, for collaboration purposes.
5. The administrator disables the global `workspace.tools` permission.
6. Bob updates the tool's content via the `POST /api/v1/tools/id/{id}/update` endpoint with malicious Python code.
7. Due to the missing `workspace.tools` check, the malicious code is executed on the server.
8. Bob achieves code execution and potentially gains unauthorized access to sensitive information or systems.

## Impact

This vulnerability allows an untrusted user to bypass intended security restrictions and execute arbitrary code on the Open WebUI server. Successful exploitation can lead to privilege escalation, potentially granting the attacker full control over the Open WebUI instance and access to sensitive data. The impact includes potential data breaches, system compromise, and unauthorized access to connected systems. The vulnerability affects all installations where an administrator has granted write access to tools to users without `workspace.tools` permissions, even if the global `workspace.tools` permission is subsequently revoked.

## Recommendation

*   Apply the patch provided by Open WebUI to re-introduce the `workspace.tools` permission check on the tool update endpoint.
*   Deploy the Sigma rule `Detect Open WebUI Tool Update Endpoint Bypass` to detect attempts to exploit this vulnerability based on request paths.
*   Review existing user permissions and revoke write access to tools for any untrusted users who do not have the `workspace.tools` permission.
*   Monitor web server logs for suspicious POST requests to the `/api/v1/tools/id/{id}/update` endpoint (category `webserver`) originating from unexpected IP addresses.
