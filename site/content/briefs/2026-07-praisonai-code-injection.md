---
title: PraisonAI Code Injection Vulnerability (CVE-2026-61444)
slug: 2026-07-praisonai-code-injection
description: PraisonAI versions prior to 4.6.78 are vulnerable to a critical code injection flaw within the deploy/api.py component, allowing authenticated attackers with high privileges to inject and execute arbitrary Python code via an unsanitized 'agents_file' parameter, leading to remote code execution.
date: "2026-07-10T15:19:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code-injection
  - RCE
  - web-application
  - python
vendors:
  - MervinPraison
products:
  - PraisonAI (< 4.6.78)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1213
    technique_name: Exploit Public-Facing Application
    evidence: PraisonAI versions before 4.6.78 contain a code injection vulnerability in deploy/api.py where the agents_file parameter is directly interpolated into an f-string without sanitization.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can inject arbitrary Python code that executes when the generated server code runs via subprocess.Popen().
    confidence_band: high
cves:
  - id: CVE-2026-61444
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61444
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-g6j7-pffp-8whg
  - https://www.vulncheck.com/advisories/praisonai-before-code-injection-via-f-string
rules:
  - title: Detects CVE-2026-61444 Exploitation - PraisonAI Code Injection Attempt
    description: Detects CVE-2026-61444 exploitation attempts targeting PraisonAI's deploy/api.py endpoint by looking for Python code injection indicators in the 'agents_file' parameter within web server logs.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.006
      - T1213
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-61444 describes a critical code injection vulnerability affecting PraisonAI versions prior to 4.6.78. This flaw resides in the `deploy/api.py` component, where the `agents_file` parameter is directly interpolated into an f-string without proper sanitization. An authenticated attacker with high privileges can exploit this by injecting arbitrary Python code into the `agents_file` parameter. When the application's generated server code runs this unsanitized input via `subprocess.Popen()`, the injected Python code executes on the server, leading to remote code execution. This vulnerability presents a severe risk for organizations using vulnerable PraisonAI instances, allowing a privileged attacker to gain full control over the underlying system by leveraging their existing access.

## Attack Chain

1. An attacker first obtains or possesses high-privileged, authenticated access to a PraisonAI instance.
2. The attacker identifies the `deploy/api.py` endpoint and the `agents_file` parameter within the vulnerable PraisonAI application (versions prior to 4.6.78).
3. The attacker crafts a malicious HTTP request, typically a POST request, targeting the `deploy/api.py` endpoint of the PraisonAI server.
4. Within this request, the `agents_file` parameter is supplied with a specially crafted string containing arbitrary Python code designed to break out of the f-string context and inject executable commands.
5. The PraisonAI application receives the authenticated request, and the vulnerable code in `deploy/api.py` processes the malicious `agents_file` parameter.
6. The unsanitized `agents_file` value is directly interpolated into an f-string, which is used to dynamically generate server code, thereby embedding the attacker's malicious Python payload.
7. The generated server code, now containing the injected malicious Python, is executed on the host system via `subprocess.Popen()`.
8. The injected Python code executes with the privileges of the PraisonAI process, resulting in remote code execution (RCE) and potential full compromise of the underlying server.

## Impact

Successful exploitation of CVE-2026-61444 allows an attacker with high-privileged access to achieve remote code execution on the server hosting the PraisonAI application. This can lead to complete compromise of the underlying system, enabling the attacker to execute arbitrary commands, access sensitive data, modify or delete files, and establish persistent access. The impact includes severe data breaches, system integrity compromise, and potentially further lateral movement within the compromised network. While requiring high privileges, the vulnerability's ease of exploitation once privileges are obtained makes it a critical concern for affected organizations.

## Recommendation

* Patch CVE-2026-61444 immediately by upgrading PraisonAI to version 4.6.78 or later, as specified by the vendor.
* Deploy the Sigma rule "Detects CVE-2026-61444 Exploitation - PraisonAI Code Injection Attempt" to your SIEM and monitor web server logs for suspicious requests to `/deploy/api.py` containing code injection indicators.
* Implement strict access controls and regular auditing for high-privileged accounts interacting with the PraisonAI application.
