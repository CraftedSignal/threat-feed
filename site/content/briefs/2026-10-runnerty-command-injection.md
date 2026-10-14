---
title: OS Command Injection in @runnerty/executor-decompress
slug: 2026-10-runnerty-command-injection
description: The @runnerty/executor-decompress package is vulnerable to OS command injection via crafted archive filenames, allowing arbitrary command execution within the Runnerty process context.
date: "2026-10-14T16:37:46Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:runnerty:executor_decompress:*:*:*:*:*:*:*:*
tags:
  - command-injection
  - rce
  - vulnerability
vendors:
  - Runnerty
products:
  - executor-decompress (<= 3.1.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: The package contains an OS command injection vulnerability that allows attackers to execute commands by supplying crafted archive file names to compress_file.
    confidence_band: high
cves:
  - id: CVE-2026-110641
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110641
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade @runnerty/executor-decompress to a patched version
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-110641 vulnerability requires patching
  mitigation_plan:
    - priority: immediate
      action: Restrict directory access to prevent unauthorized file placement
      owner: IT Operations
      addresses: CVE-2026-110641
      evidence: Source notes attacker requires control of files in a watched directory
---

The @runnerty/executor-decompress package, up to and including version 3.1.1, contains an OS command injection vulnerability (CVE-2026-110641). This vulnerability exists in the compress_file function, which fails to properly sanitize filenames before passing them to the shelljs exec() method. An attacker who can influence the name of an archive file deposited into a watched directory can supply crafted strings containing shell metacharacters or $() command substitution syntax. When the Runnerty process attempts to process these archives, the injected commands are executed with the permissions of the underlying Runnerty process. This flaw poses a high risk to environments using Runnerty for automated workflow or file processing, as it facilitates unauthorized remote code execution.

## Impact

Successful exploitation allows for arbitrary code execution with the privileges of the Runnerty service user. Depending on the environment, this could lead to full system compromise, lateral movement within the network, or the exfiltration of sensitive configuration data managed by the workflow automation tool. There are currently no reports of widespread, active in-the-wild exploitation for this specific CVE.

## Recommendation

* Upgrade @runnerty/executor-decompress to a patched version beyond 3.1.1 immediately if available, or implement strict input validation to sanitize filenames in the watched directories before they are processed by the plugin.
* Restrict file system write access to directories monitored by Runnerty to highly trusted service accounts only to prevent unauthorized file placement.
* Monitor process execution logs for instances where shell-interpreting binaries (e.g., cmd.exe, /bin/sh) are spawned by the Runnerty process with command line arguments containing characters like '$', '(', ')', ';', or '&'.
