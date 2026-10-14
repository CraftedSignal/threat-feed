---
title: Remote Code Execution in simple-git via --config Injection
slug: 2026-10-simple-git-rce
description: CVE-2026-6951 is a remote code execution vulnerability in the simple-git library, resulting from a filter bypass that allows command injection through the --config option and the Git ext protocol.
date: "2026-10-14T14:48:31Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:simple-git_project:simple-git:*:*:*:*:*:*:*:*
  - cpe:2.3:a:simple-git_project:simple-git:*:*:*:*:*:node.js:*:*
products:
  - simple-git (< 3.36.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The --config option allows an attacker to enable the Git ext protocol and execute arbitrary commands through a URL string.
    confidence_band: high
cves:
  - id: CVE-2026-6951
    cvss: 9.8
    epss: 0.01006
  - id: CVE-2022-25912
    cvss: 8.1
    epss: 0.03077
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-EQSTLAB-CVE-2026-6951
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade simple-git to version 3.36.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source documentation identifies 3.36.0 as the fixed version.
  mitigation_plan:
    - priority: immediate
      action: 'Block the use of the ext:: protocol in Git repository URLs within application logic'
      owner: Development
      addresses: CVE-2026-6951
      evidence: Source recommends rejecting 'ext::' URLs as a defensive measure.
---

CVE-2026-6951 describes a remote code execution (RCE) vulnerability in the simple-git library (versions prior to 3.36.0) caused by an incomplete patch for CVE-2022-25912. While previous mitigations successfully restricted the use of the -c flag in Git arguments, the --config equivalent remained improperly sanitized. An attacker who can control Git arguments passed to simple-git can leverage this deficiency to enable the Git 'ext' protocol. This allows for the execution of arbitrary system commands through a specially crafted repository URL string. Because simple-git is frequently used in Node.js applications to manage version control, successful exploitation results in RCE with the privileges of the Node.js runtime process. This vulnerability is highly critical as it permits attackers to gain reverse shells, exfiltrate sensitive files, or manipulate application data.

## Attack Chain

1. Attacker identifies a web application or internal service that utilizes simple-git to perform repository operations (e.g., import or clone).
2. Attacker crafts a malicious repository string utilizing the 'ext::' prefix to trigger arbitrary command execution.
3. Attacker injects the '--config' argument and 'protocol.ext.allow=always' setting into the target application's Git options, bypassing previous input filters.
4. The victim application invokes simple-git, passing the untrusted inputs directly to the underlying Git binary.
5. The Git binary parses the '--config' argument, enabling the dangerous 'ext' protocol for the current execution context.
6. The Git process executes the command specified in the 'ext::' prefix (e.g., 'sh -c id').
7. Arbitrary code executes in the context of the Node.js application process, leading to full system compromise or persistence.

## Impact

Successful exploitation allows for unauthenticated remote code execution with the privileges of the underlying Node.js application. Potential impacts include full system compromise, exfiltration of application source code or environment variables, modification of critical data, and deployment of secondary payloads such as reverse shells. The vulnerability has been assigned a CVSS score of 9.8.

## Recommendation

* Upgrade simple-git to version 3.36.0 or later immediately to patch CVE-2026-6951.
* Implement strict input validation for all repository URLs and Git arguments accepted by the application, specifically blocking the 'ext::' protocol prefix.
* Refactor application code to avoid passing user-controlled input directly into Git configuration flags like '--config' or '-c'.
* Audit applications using simple-git to identify and restrict the passing of arbitrary array options to the library's command execution methods.
