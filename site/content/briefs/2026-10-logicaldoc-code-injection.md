---
title: Authenticated OS Command Injection in LogicalDOC Community Edition
slug: 2026-10-logicaldoc-code-injection
description: LogicalDOC Community Edition versions 9.3 and earlier are vulnerable to authenticated OS command injection via maliciously crafted Velocity templates within the DocumentService.sendAsEmail function.
date: "2026-10-12T15:42:57Z"
lastmod: "2026-10-12T15:43:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:logicaldoc:logicaldoc:*:*:*:*:community:*:*:*
tags:
  - remote-code-execution
  - injection
  - vulnerability
  - web-vulnerability
  - authorization-bypass
  - cve-2026-109201
vendors:
  - LogicalDOC
products:
  - LogicalDOC Community Edition (<= 9.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: LogicalDOC Community Edition through 9.3 contains a code injection vulnerability that allows authenticated users to execute OS commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can invoke SystemTool exec methods or ClassTool to run commands with LogicalDOC process privileges.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated users can exploit this flaw to perform unauthorized actions such as copying, retrieving, deleting, or tampering with documents.
    confidence_band: high
cves:
  - id: CVE-2026-109199
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109199
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109201
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review access logs for DocumentService.sendAsEmail activity from unauthorized accounts
      owner: SOC
      due: 24h
      evidence: CVE-2026-109199 indicates exploit vector resides in DocumentService
  mitigation_plan:
    - priority: immediate
      action: Upgrade LogicalDOC Community Edition to the latest patched version
      owner: IT Operations
      addresses: CVE-2026-109199
      evidence: NVD vulnerability entry
updates:
  - at: "2026-10-12T15:43:04Z"
    level: L2
    summary: added coverage for LogicalDOC Community Edition (<= 9.3)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109201
---

LogicalDOC Community Edition through version 9.3 contains a critical code injection vulnerability (CVE-2026-109199) that allows authenticated users to execute arbitrary operating system commands. The vulnerability exists within the 'DocumentService.sendAsEmail' function, which processes user-supplied input for the subject and message fields using the Apache Velocity template engine. 

Attackers can leverage this input to submit malicious Velocity templates that invoke sensitive Java classes, specifically 'SystemTool' or 'ClassTool'. These methods allow for the execution of system commands, effectively bypassing the 'forbidRuntimeUsage' denylist implemented by the application. Because the commands are executed with the privileges of the LogicalDOC service process, successful exploitation results in full remote code execution on the underlying host, potentially leading to total system compromise. This vulnerability requires an authenticated session, making it a significant risk for organizations using LogicalDOC in internal or public-facing environments.

## Attack Chain

1. Attacker authenticates to the LogicalDOC web interface with valid user credentials.
2. Attacker navigates to the email functionality provided by the 'DocumentService' component.
3. Attacker crafts a request targeting the 'sendAsEmail' operation.
4. Attacker injects a malicious Velocity template payload into the 'subject' or 'message' parameters.
5. Attacker embeds calls to 'SystemTool.exec()' or 'ClassTool' within the template to bypass 'forbidRuntimeUsage' filters.
6. The application server parses the malicious template during the email generation process.
7. The Java Virtual Machine executes the injected OS commands with the permissions of the web application user.
8. Attacker achieves remote code execution, enabling further lateral movement or data exfiltration.

## Impact

Successful exploitation of CVE-2026-109199 allows an authenticated attacker to execute arbitrary commands on the application server. This can result in complete system compromise, unauthorized access to sensitive documents managed by LogicalDOC, and lateral movement within the network. The scope of impact includes any infrastructure running LogicalDOC Community Edition version 9.3 or earlier.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

- Identify and restrict access to the 'DocumentService' endpoints for users who do not require email functionality.
- Implement Web Application Firewall (WAF) rules to inspect POST requests to the 'DocumentService' for Velocity template syntax, such as '$class.inspect', 'SystemTool', or 'ClassTool'.
- Monitor web server logs for suspicious payload patterns in 'subject' or 'message' fields associated with the 'sendAsEmail' method.
- Patch LogicalDOC Community Edition to the latest available version once a security update addressing CVE-2026-109199 is released by LogicalDOC.
