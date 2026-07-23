---
title: 'CVE-2026-63766: Unauthenticated OS Command Injection in GPT-SoVITS webui.py'
slug: 2026-07-gpt-sovits-os-command-injection
description: An unauthenticated OS command injection vulnerability (CVE-2026-63766) in GPT-SoVITS through version 20250606v2pro's webui.py allows attackers to execute arbitrary operating system commands via shell metacharacters in Gradio textbox inputs, leading to remote code execution.
date: "2026-07-20T20:18:01Z"
lastmod: "2026-07-23T12:03:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=37D5777E-3101-5732-B15F-FEBD39E19E6F&utm_source=rss&utm_medium=rss
tags:
  - command-injection
  - rce
  - web-vulnerability
  - ai/ml-model
  - cve
vendors:
  - RVC-Boss
products:
  - GPT-SoVITS through 20250606v2pro
  - GPT-SoVITS <= 20250606v2pro
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can inject shell metacharacters through path parameters to execute arbitrary OS commands as the server process user without authentication.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: OS command injection vulnerability in webui.py where ASR, slice, denoise, and uvr5 functions interpolate unsanitized Gradio textbox values directly into shell commands executed with shell=True.
    confidence_band: high
cves:
  - id: CVE-2026-63766
    cvss: 9.8
    epss: 0.0139
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63766
  - https://github.com/RVC-Boss/GPT-SoVITS/issues/2793
  - https://www.vulncheck.com/advisories/gpt-sovits-20250606v2pro-os-command-injection-via-webui-py
  - https://sploitus.com/exploit?id=37D5777E-3101-5732-B15F-FEBD39E19E6F&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=37D5777E-3101-5732-B15F-FEBD39E19E6F
  - type: url
    value: https://github.com/RVC-Boss/GPT-SoVITS
ioc_counts:
  url: 2
rules:
  - title: Detects CVE-2026-63766 Exploitation - GPT-SoVITS OS Command Injection
    description: Detects CVE-2026-63766 exploitation attempts in GPT-SoVITS webui.py by identifying HTTP requests targeting vulnerable functions with shell metacharacters in the URI query or path.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-23T12:03:01Z"
    level: L2
    summary: poc_available; OS linux
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=37D5777E-3101-5732-B15F-FEBD39E19E6F&utm_source=rss&utm_medium=rss
---

GPT-SoVITS, a platform for text-to-speech and voice cloning, is affected by a critical OS command injection vulnerability, CVE-2026-63766, impacting versions through 20250606v2pro. This flaw resides in the `webui.py` component, specifically within the `ASR`, `slice`, `denoise`, and `uvr5` functions. These functions insecurely interpolate unsanitized Gradio textbox values directly into shell commands executed with `shell=True`. An unauthenticated attacker can exploit this by injecting shell metacharacters (e.g., semicolons, pipes, ampersands) through path parameters in HTTP requests. Successful exploitation grants the attacker arbitrary OS command execution privileges, running commands as the user associated with the GPT-SoVITS server process, potentially leading to full system compromise. The vulnerability has a CVSS v3.1 base score of 9.8, indicating a critical severity and ease of exploitation.

## Attack Chain

1. An unauthenticated attacker sends a specially crafted HTTP request to the vulnerable GPT-SoVITS web interface.
2. The request targets a susceptible function within `webui.py`, such as `ASR`, `slice`, `denoise`, or `uvr5`.
3. The attacker injects shell metacharacters (e.g., `;`, `|`, `&&`, `$()`) into a path parameter or Gradio textbox input that is not properly sanitized.
4. The vulnerable Python code in `webui.py` interpolates the unsanitized malicious input directly into a system command executed using a shell (e.g., `subprocess.run(..., shell=True)`).
5. The operating system's shell processes the combined command string, interpreting the injected metacharacters as distinct commands.
6. The attacker's arbitrary commands are executed on the server, typically with the privileges of the GPT-SoVITS application user.
7. The attacker gains remote code execution, potentially enabling persistent access, data exfiltration, or further lateral movement within the network.

## Impact

Successful exploitation of CVE-2026-63766 results in unauthenticated remote code execution (RCE) on the server hosting GPT-SoVITS. Given the CVSS v3.1 score of 9.8 (Critical), this vulnerability allows for complete compromise of confidentiality, integrity, and availability of the affected system. Attackers can execute any command with the privileges of the server process, enabling them to install backdoors, steal sensitive data, modify system configurations, or deploy further malicious payloads. Organizations using GPT-SoVITS for AI/ML model inference or development could face significant data breaches, operational disruption, and reputational damage.

## Recommendation

* Patch GPT-SoVITS to a version beyond 20250606v2pro to remediate CVE-2026-63766 immediately.
* Deploy the provided Sigma rule to your SIEM to detect exploitation attempts targeting `webui.py` with shell metacharacters.
* Monitor web server access logs and application logs for unusual HTTP requests to `webui.py` or unexpected command execution originating from the GPT-SoVITS process.
* Implement strong input validation for all user-supplied data, especially in web applications, to prevent similar command injection vulnerabilities.
