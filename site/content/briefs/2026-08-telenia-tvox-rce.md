---
title: OS Command Injection in Telenia Software TVox
slug: 2026-08-telenia-tvox-rce
description: Telenia Software TVox contains an OS command injection vulnerability in action_audio.php that allows authenticated attackers to execute arbitrary system commands as the apache user.
date: "2026-08-03T16:05:10Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Telenia Software
products:
  - TVox (26.x)
  - TVox (24.x)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The application passes an unsanitized pid parameter into an exec() call when the action parameter is set to checkProcess.
    confidence_band: high
cves:
  - id: CVE-2026-67608
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67608
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch TVox instances to the latest secure version.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-67608 advisory
  hunt_leads:
    - lead: Search logs for HTTP requests to /action_audio.php containing shell injection characters in pid parameter.
      technique_id: T1059.003
      data_needed:
        - Web server access logs (URI stem, query parameters)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability analysis identifies action_audio.php as the injection vector.
---

Telenia Software TVox versions 26.5.3 and prior, as well as 24.9.21 and prior, contain a critical OS command injection vulnerability. The flaw exists in the 'action_audio.php' script, which improperly sanitizes user-supplied input. An authenticated attacker can exploit this by sending a crafted HTTP request where the 'action' parameter is set to 'checkProcess' and the 'pid' parameter contains malicious shell metacharacters. The underlying application uses the 'pid' input directly within an exec() system call. Successful exploitation allows an attacker to execute arbitrary operating system commands with the privileges of the web server (apache) user. This vulnerability impacts the core functionality of the TVox platform and poses a significant risk for lateral movement and system compromise.

## Impact

Successful exploitation allows unprivileged authenticated attackers to escalate their control to arbitrary code execution at the web server level. This provides a foothold for further malicious activity, such as data exfiltration, internal network reconnaissance, or the deployment of additional payloads within the TVox environment.

## Recommendation

- Update Telenia Software TVox to version 26.5.4 or 24.9.22 immediately to patch CVE-2026-67608.
- Review web server access logs for anomalous POST or GET requests to 'action_audio.php' containing shell metacharacters such as semicolon, pipe, or backticks in the 'pid' parameter.
- Implement request validation at the Web Application Firewall (WAF) layer to block common command injection strings targeting the 'pid' parameter in the identified file.
