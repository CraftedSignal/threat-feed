---
title: Open WebUI Code Execution Bypass via Feature Gate Neglect (CVE-2026-45672)
slug: 2026-05-open-webui-code-exec-bypass
description: Open WebUI versions 0.8.11 and earlier are vulnerable to arbitrary code execution due to a bypassed feature gate; the `/api/v1/utils/code/execute` endpoint allows authenticated users to execute Python code via Jupyter even when code execution is disabled, leading to potential data exfiltration and code execution (CVE-2026-45672).
date: "2026-05-14T20:30:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-execution
  - feature-bypass
  - web-application
vendors:
  - Open WebUI
products:
  - open-webui (<= 0.8.11)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-482j-2pq6-q5w4
  - https://github.com/open-webui/open-webui/commit/6d736d3c598dbe49488675ed42845e00b62dfcba
rules:
  - title: Detect Open WebUI Code Execution Bypass via API Endpoint
    description: Detects CVE-2026-45672 exploitation — attempts to execute code via the `/api/v1/utils/code/execute` endpoint in Open WebUI, bypassing the `ENABLE_CODE_EXECUTION` flag.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.009
    data_sources:
      - webserver
  - title: Detect Open WebUI Jupyter Code Execution with Suspicious Commands
    description: Detects CVE-2026-45672 exploitation — monitors for specific command execution attempts within Open WebUI's Jupyter code execution feature, indicating potential exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.009
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI versions 0.8.11 and earlier are vulnerable to a code execution bypass. The vulnerability resides in the `/api/v1/utils/code/execute` endpoint, which incorrectly allows authenticated users to execute arbitrary Python code via the Jupyter server, even when the administrator has explicitly disabled code execution by setting `ENABLE_CODE_EXECUTION=false` in the application configuration. This issue was verified against Open WebUI v0.8.11 running in a Docker container on March 25, 2026. The absence of proper authorization checks on this API endpoint makes the configured feature gate ineffective, thereby creating a security loophole that could be exploited to gain unauthorized access and control over the system's internal services.

## Attack Chain

1. An attacker authenticates to the Open WebUI application as a valid user.
2. The attacker crafts a POST request to the `/api/v1/utils/code/execute` endpoint.
3. The POST request includes a JSON payload containing the `code` parameter with the Python code to be executed. Example: `{"code":"import os; print(os.popen(\"id\").read())"}`
4. The Open WebUI backend receives the request and, without checking the `ENABLE_CODE_EXECUTION` flag, forwards the code to the connected Jupyter server.
5. The Jupyter server executes the provided Python code within its container.
6. The executed code uses the `os.popen()` function to execute shell commands.
7. The Jupyter container, due to its network configuration, can access internal Docker services.
8. The attacker obtains the output of the executed code and any internal service data accessible from the Jupyter container, potentially exfiltrating sensitive information.

## Impact

The vulnerability allows any authenticated user to execute arbitrary Python code in the Jupyter container, even when code execution is disabled. This leads to: arbitrary code execution in the Jupyter container, giving the attacker the ability to read files and spawn processes; network access to internal Docker services; data exfiltration from internal services; rendering the admin's security configuration ineffective and creating a false sense of security for users who believe code execution is disabled.

## Recommendation

*   Upgrade Open WebUI to version 0.8.12 or later to patch CVE-2026-45672, as the vulnerability has been fixed in this version.
*   Deploy the Sigma rule "Detect Open WebUI Code Execution Bypass via API Endpoint" to monitor for requests to the `/api/v1/utils/code/execute` endpoint.
*   Review the network configuration of the Jupyter container to restrict access to internal Docker services, mitigating the potential impact of successful code execution.
