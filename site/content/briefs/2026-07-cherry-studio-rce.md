---
title: Cherry Studio Remote Code Execution Vulnerability (CVE-2026-40501)
slug: 2026-07-cherry-studio-rce
description: A remote code execution vulnerability, CVE-2026-40501, exists in Cherry Studio versions 1.2.2 through 1.9.12 due to improper Electron BrowserWindow configuration, allowing remote attackers to execute arbitrary code by injecting malicious JavaScript through controlled search provider content, thereby gaining full Node.js privileges and accessing system resources.
date: "2026-07-15T18:21:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - electron-vulnerability
  - application-security
vendors:
  - Cherry Studio
products:
  - Cherry Studio 1.2.2
  - Cherry Studio 1.9.12
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers ... can execute JavaScript with full Node.js privileges, gaining access to fs, child_process, os, and process.env under the operating-system account of the Cherry Studio process.
    confidence_band: high
cves:
  - id: CVE-2026-40501
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40501
rules:
  - title: Detects CVE-2026-40501 Exploitation - Child Process Creation by Cherry Studio
    description: Detects suspicious child process creation by the vulnerable Cherry Studio application, indicative of remote code execution via CVE-2026-40501. The vulnerability allows malicious JavaScript executed within Cherry Studio to leverage Node.js 'child_process' module to spawn arbitrary system commands.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

A critical remote code execution (RCE) vulnerability, tracked as CVE-2026-40501, has been identified in Cherry Studio versions 1.2.2 through 1.9.12. This flaw stems from an insecure configuration within the Electron framework used by the application, specifically within its `SearchService`. The Electron `BrowserWindow` is configured with `nodeIntegration` enabled and `contextIsolation` disabled, which creates a dangerous attack surface. Remote attackers can exploit this by delivering malicious JavaScript through content they control, such as a compromised search engine provider, individual search result pages, or manipulated provider settings. Upon execution, the malicious JavaScript gains full Node.js privileges, allowing access to sensitive system modules like `fs`, `child_process`, `os`, and `process.env`, enabling the attacker to execute arbitrary code under the operating-system account running Cherry Studio. This vulnerability poses a significant risk to users running affected versions of Cherry Studio.

## Attack Chain

1. Attacker establishes control over content served by a search provider or specific search result pages configured within Cherry Studio.
2. A Cherry Studio user navigates to or interacts with the attacker-controlled content through the application's SearchService.
3. Malicious JavaScript is delivered to the user's Cherry Studio application from the attacker-controlled source.
4. The Electron BrowserWindow within Cherry Studio, misconfigured with `nodeIntegration` enabled and `contextIsolation` disabled, loads and executes the malicious JavaScript.
5. The executed JavaScript gains full Node.js privileges within the Cherry Studio process due to the insecure Electron configuration.
6. The malicious JavaScript utilizes Node.js modules, such as `child_process`, `fs`, `os`, and `process.env`, to interact with the underlying operating system.
7. Arbitrary code is executed under the privileges of the operating-system account running the Cherry Studio process, leading to system compromise and potential data exfiltration or further malware deployment.

## Impact

Successful exploitation of CVE-2026-40501 results in complete remote code execution on the victim's system, operating with the privileges of the user running Cherry Studio. This level of access allows attackers to install persistent malware, steal sensitive data, modify system configurations, or launch further attacks within the network. While specific victim counts or targeted sectors are not detailed in the advisory, any organization or individual using the vulnerable Cherry Studio versions could be severely impacted. The direct access to file systems and the ability to spawn child processes means an attacker can fully compromise the host machine.

## Recommendation

* Patch CVE-2026-40501 immediately by upgrading Cherry Studio to a version beyond 1.9.12, which includes commit 1518530.
* Deploy the `Detects CVE-2026-40501 Exploitation - Child Process Creation by Cherry Studio` Sigma rule to detect suspicious process activity originating from the Cherry Studio application.
* Ensure Sysmon process-creation logging is enabled to activate the above rule and provide necessary telemetry.
