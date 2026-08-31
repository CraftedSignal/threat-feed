---
title: Remote Code Execution in GitList via OS Command Injection
slug: 2026-08-gitlist-rce
description: GitList version 2.0.0 contains an OS command injection vulnerability in the getDefaultBranch function, allowing unauthenticated remote attackers to execute arbitrary system commands.
date: "2026-08-31T11:17:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:klaussilveira:gitlist:2.0.0:*:*:*:*:*:*:*
tags:
  - web-application
  - rce
  - os-command-injection
vendors:
  - klaussilveira
products:
  - GitList (2.0.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Such manipulation leads to os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-82668
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82668
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade GitList from 2.0.0 to 3.0.0-beta
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 3.0.0-beta addresses this issue.
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the GitList management interface
      owner: IT Operations
      addresses: CVE-2026-82668
      evidence: The attack can be executed remotely.
---

A remote code execution vulnerability (CVE-2026-82668) exists in klaussilveira GitList version 2.0.0. The vulnerability resides within the getDefaultBranch function located in the file src/SCM/System/Git/CommandLine.php. An attacker can exploit this flaw by providing crafted, unsanitized input to the application, which is then concatenated into a system command and executed by the underlying server. Since the vulnerability can be triggered remotely without authentication, it poses a significant risk to any publicly facing GitList installation. Proof-of-concept exploit code has been publicly disclosed, increasing the likelihood of opportunistic exploitation. The vendor has addressed this issue in version 3.0.0-beta via patch 88cf2866083d5f7c20d9d565c45f828a7ad1516b. Users are strongly advised to upgrade their instances immediately to remediate the flaw.

## Impact

Successful exploitation of this vulnerability results in full remote code execution on the host server. This allows an attacker to compromise the confidentiality, integrity, and availability of the repository server, potentially leading to unauthorized data access, further lateral movement within the network, or deployment of additional malware.

## Recommendation

Prioritize the upgrade of all internet-facing GitList 2.0.0 instances to version 3.0.0-beta as indicated in the vendor security advisory. If immediate patching is not feasible, restrict network access to the GitList interface to trusted management networks and audit server logs for unusual process execution patterns stemming from the web server user context.
