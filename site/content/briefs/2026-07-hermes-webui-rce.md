---
title: Critical RCE Vulnerability in Hermes WebUI (CVE-2026-58123)
slug: 2026-07-hermes-webui-rce
description: An unauthenticated remote code execution vulnerability, CVE-2026-58123, exists in Hermes WebUI versions prior to 0.51.788, allowing remote attackers to execute arbitrary shell commands by accessing exposed terminal API endpoints without credentials, leading to full command execution as the server process user.
date: "2026-07-09T22:19:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - rce
  - web-exploitation
  - hermes
  - api-exploitation
products:
  - Hermes WebUI < 0.51.788
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Hermes WebUI before 0.51.788 contains an unauthenticated remote code execution vulnerability that allows remote attackers to execute arbitrary shell commands by accessing the embedded terminal API endpoints without credentials.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can [...] write arbitrary commands through the terminal input endpoint to achieve full command execution as the server process user.
    confidence_band: high
cves:
  - id: CVE-2026-58123
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58123
rules:
  - title: Detects CVE-2026-58123 Exploitation - Hermes WebUI Unauthenticated RCE
    description: Detects CVE-2026-58123 exploitation attempts targeting Hermes WebUI by identifying suspicious HTTP requests to terminal API endpoints containing common shell command injection characters.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-58123 is a critical unauthenticated remote code execution (RCE) vulnerability affecting Hermes WebUI versions before 0.51.788. Published on July 9, 2026, this flaw allows any remote attacker to execute arbitrary shell commands on the underlying server. Attackers can leverage this by directly accessing embedded terminal API endpoints that are exposed without proper authentication. The exploitation involves a sequence of four unauthenticated HTTP requests: establishing a session, attaching a pseudo-terminal (PTY) shell, and subsequently writing arbitrary commands to the terminal input endpoint. This grants the attacker full command execution privileges under the context of the server process user, posing a severe risk of system compromise, data exfiltration, or further network penetration.

## Attack Chain

1. **Initial Access**: An unauthenticated remote attacker sends an HTTP request to an exposed Hermes WebUI terminal API endpoint.
2. **Session Creation**: The attacker sends a second HTTP request to establish a session with the embedded terminal without requiring any authentication.
3. **PTY Shell Attachment**: A third unauthenticated HTTP request is sent by the attacker to attach a PTY shell to the newly created session.
4. **Command Injection**: The attacker sends a fourth unauthenticated HTTP request to the terminal input endpoint, embedding arbitrary shell commands within the request.
5. **Command Execution**: The Hermes WebUI server processes the request and executes the injected shell commands as the user account running the WebUI process.
6. **Impact**: The attacker achieves full remote code execution, potentially leading to system compromise, data exfiltration, or further lateral movement within the compromised network.

## Impact

Successful exploitation of CVE-2026-58123 results in unauthenticated remote code execution on the server hosting Hermes WebUI. This allows attackers to gain full control over the affected system under the privileges of the server process user. The consequences can include complete system compromise, unauthorized access to sensitive data, installation of malware (e.g., ransomware, cryptominers), establishment of persistent backdoors, and the use of the compromised system as a pivot point for further attacks within the organization's network.

## Recommendation

* Immediately update Hermes WebUI to version 0.51.788 or later to patch CVE-2026-58123.
* Deploy the Sigma rule provided in this brief to your SIEM to detect attempts to exploit the Hermes WebUI terminal API.
* Ensure proper network segmentation and firewall rules are in place to restrict access to Hermes WebUI instances from untrusted networks.
