---
title: CVE-2026-73682 Remote Code Execution in Semaphore
slug: 2026-08-semaphore-rce
description: Semaphore versions prior to 2.18.20 contain an argument injection vulnerability allowing authenticated users with Manager or Owner roles to achieve remote code execution via malicious git_url parameters.
date: "2026-08-14T22:14:39Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Semaphore
products:
  - Semaphore (< 2.18.20)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can craft a malicious git_url value using git's --upload-pack= option to inject and execute arbitrary shell commands when the server processes repository operations using the default cmd_git client.
    confidence_band: high
cves:
  - id: CVE-2026-73682
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73682
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Semaphore to 2.18.20
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-73682 patch availability
  mitigation_plan:
    - priority: immediate
      action: Review and restrict Manager/Owner roles
      owner: IT Operations
      addresses: CVE-2026-73682
      evidence: Exploit requires Manager or Owner roles
---

Semaphore versions prior to 2.18.20 are affected by an OS command injection vulnerability, specifically categorized as argument injection. The flaw exists in the handling of repository 'git_url' configurations. Authenticated users assigned the 'Manager' or 'Owner' role on any project can exploit this by crafting a malicious 'git_url' string containing the '--upload-pack=' git option. 

When the application processes repository operations using the internal 'cmd_git' client, the crafted input allows the injection of arbitrary shell commands. Because the 'cmd_git' client executes these commands with the privileges of the Semaphore server application, successful exploitation results in remote code execution on the underlying server host. Given the elevated roles required (Manager/Owner), this vulnerability represents a significant risk for lateral movement or persistence within the CI/CD pipeline infrastructure.

## Impact

The vulnerability poses a critical risk to the integrity and availability of Semaphore instances. Successful exploitation allows unauthorized execution of system commands, potentially leading to full system compromise, exfiltration of sensitive source code, or modification of deployment pipelines. Organizations using Semaphore versions below 2.18.20 are impacted, particularly those with internal project environments where account security might be lower or trust models rely on the internal authorization framework.

## Recommendation

* Upgrade all instances of Semaphore to version 2.18.20 or later immediately to patch CVE-2026-73682.
* Audit project roles to identify and restrict 'Manager' or 'Owner' permissions to only necessary personnel to minimize the potential attack surface.
* Implement egress filtering on the Semaphore server to prevent the execution of outbound payloads or connection to attacker-controlled C2 infrastructure in the event of successful command injection.
