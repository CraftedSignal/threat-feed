---
title: OS Command Injection in Corget GpsDget
slug: 2026-08-corget-rce
description: Corget GpsDget 2_3.2 is vulnerable to unauthenticated OS command injection via the HTTP SendEmail method, allowing root-level code execution.
date: "2026-08-10T14:37:45Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Corget
products:
  - GpsDget 2_3.2
affected_os:
  - Ubuntu
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows an unauthenticated attacker to inject arbitrary shell commands via the Target header.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The application insecurely concatenates user input into a system() call.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52631
rules:
  - title: Detect Corget GpsDget OS Command Injection Attempt
    description: Detects exploitation attempts against Corget GpsDget by identifying malicious shell metacharacters in the Target header of a POST request.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy web application firewall (WAF) rules to inspect and block HTTP POST requests containing shell metacharacters in the Target header
      owner: SOC
      due: 24h
      evidence: Source explicitly states exploit uses shell metacharacters in the Target header
  mitigation_plan:
    - priority: immediate
      action: Disable the SendEmail method in the PTTServer configuration or restrict network access to the server
      owner: IT Operations
      addresses: Unauthenticated RCE in Corget GpsDget
      evidence: Exploit targets the SendEmail functionality
---

Corget GpsDget version 2_3.2 contains an OS command injection vulnerability within its PTTServer HTTP service. The flaw resides in the handling of the 'Target' header during a POST request to the 'SendEmail' method. Analysis of the HttpHandler.cpp source code reveals that user-supplied input from the 'Target' header is insecurely concatenated into a system() call without proper sanitization. 

This vulnerability allows unauthenticated remote attackers to inject arbitrary shell commands. Because the service executes these commands with root privileges, exploitation results in full system compromise. The issue was identified in GpsDget version 2_3.2 (build 2020-09-01) of the Gps2.0 product line. Defenders should note that this vulnerability has an active public proof-of-concept exploit available (EDB-52631), which specifically targets the PTTServer component.

## Attack Chain

1. Attacker performs reconnaissance to identify systems running the PTTServer service via public exposure.
2. Attacker crafts a malicious HTTP POST request to the target web service.
3. The request includes the 'Method' header set to 'SendEmail'.
4. The request includes a malicious payload in the 'Target' header containing shell metacharacters (e.g., x;&lt;cmd>;).
5. The PTTServer application parses the headers and passes the 'Target' value directly to a system() call.
6. The underlying operating system executes the injected shell command as the root user.
7. Attacker achieves persistent access, data exfiltration, or further lateral movement from the compromised host.

## Impact

Successful exploitation grants an unauthenticated attacker full root-level control over the target system. This allows for total compromise of the affected device, including data theft, installation of backdoors, or use of the device in further attacks. As this service is often used in GPS and PTT infrastructure, this vulnerability represents a significant threat to internal operational systems.

## Recommendation

Prioritize the identification of all internet-facing instances of Corget GpsDget and restrict access to the PTTServer interface. If patching is unavailable, implement network-level egress filtering and proxy inspection to block HTTP requests containing suspicious shell metacharacters in the 'Target' header. Monitor system logs for unexpected execution of system utilities or shell commands originating from the GpsDget process or user.
