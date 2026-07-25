---
title: SiYuan Missing Authorization Vulnerability in /mcp Endpoint (CVE-2026-66012)
slug: 2026-07-siyuan-mcp-authz
description: A critical missing authorization vulnerability, CVE-2026-66012, in SiYuan before version 3.7.2 allows a remote unauthenticated attacker to exploit the POST /mcp kernel endpoint when the Publish server is in anonymous mode, leading to arbitrary file writes, sensitive credential exposure, malicious plugin execution, and ultimately administrator takeover on affected systems.
date: "2026-07-25T11:19:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - rce
  - authorization-bypass
  - siyuan
  - cve-2026-66012
vendors:
  - SiYuan
products:
  - SiYuan < v3.7.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SiYuan before v3.7.2 contains a missing authorization vulnerability in the POST /mcp kernel endpoint... allowing a remote unauthenticated attacker to reach /mcp.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The attacker can read conf/conf.json to extract accessAuthCode, api.token, and cookieKey in plaintext
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: plant a plugin into data/plugins/ that executes with nodeIntegration:true and no contextIsolation on the next desktop launch
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: plant a plugin into data/plugins/ that executes with nodeIntegration:true and no contextIsolation
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: leading to administrator takeover.
    confidence_band: high
cves:
  - id: CVE-2026-66012
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66012
---

A critical missing authorization vulnerability, tracked as CVE-2026-66012, affects SiYuan versions prior to 3.7.2. This flaw exists in the POST /mcp kernel endpoint, which lacks proper administrative role enforcement and is only protected by a general authentication check. When the SiYuan Publish server is configured in anonymous mode (Conf.Publish.Enable=true and Conf.Publish.Auth.Enable=false), a remote unauthenticated attacker can exploit this vulnerability. The Publish reverse proxy, in this configuration, attaches an anonymous RoleReader JWT to proxied requests, granting the attacker access to 31 internal MCP tools. These tools include a file utility with comprehensive read, write, delete, rename, and copy capabilities across the entire workspace. Exploitation enables attackers to read sensitive configuration files containing plaintext API tokens and cookies, write arbitrary files, and plant malicious plugins that execute with elevated privileges upon the next desktop application launch, leading to complete system compromise and administrator takeover.

## Attack Chain

1. The SiYuan Publish server is enabled in anonymous mode, specifically with `Conf.Publish.Enable=true` and `Conf.Publish.Auth.Enable=false`.
2. A remote unauthenticated attacker initiates a request targeting the `/mcp` kernel endpoint.
3. The Publish reverse proxy intercepts the request and, due to the anonymous configuration, attaches an anonymous `RoleReader` JWT to it before forwarding to the kernel.
4. The attacker leverages the compromised access to the `/mcp` endpoint's "file tool" to read `conf/conf.json`.
5. Sensitive credentials, including `accessAuthCode`, `api.token`, and `cookieKey`, are extracted by the attacker from the plaintext `conf.json` file.
6. Using the file tool's capabilities, the attacker writes arbitrary files into the SiYuan workspace.
7. The attacker plants a malicious plugin into the `data/plugins/` directory within the SiYuan application data path.
8. Upon the next desktop launch of the SiYuan application, the malicious plugin executes with `nodeIntegration:true` and no `contextIsolation`, resulting in administrator takeover of the underlying system.

## Impact

Successful exploitation of CVE-2026-66012 allows a remote unauthenticated attacker to achieve full administrator takeover of the system running the vulnerable SiYuan desktop application. This includes the ability to read and exfiltrate sensitive configuration data containing API tokens and session cookies, manipulate or destroy any data within the SiYuan workspace, and execute arbitrary code with the privileges of the desktop user. The CVSS v3.1 Base Score of 10.0 reflects the critical nature and severe consequences of this vulnerability, affecting all users of SiYuan desktop clients before version 3.7.2 operating with a misconfigured Publish server.

## Recommendation

* Patch CVE-2026-66012 immediately by upgrading SiYuan to version 3.7.2 or later to address the missing authorization vulnerability.
* Review the SiYuan Publish server configuration. Ensure that `Conf.Publish.Enable` is not set to `true` concurrently with `Conf.Publish.Auth.Enable` set to `false`. Enable authentication for the Publish server.
* Implement file integrity monitoring for the `data/plugins/` directory within your SiYuan application workspace to detect unauthorized modifications or additions.
* Monitor for unusual process creation events originating from the SiYuan desktop client application, especially any child processes launched with suspicious arguments or exhibiting elevated privileges not typically associated with legitimate SiYuan operations.
