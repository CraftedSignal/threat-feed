---
title: OS Command Injection in Stills via Crafted Media File Paths
slug: 2026-10-stills-command-injection
description: Stills versions prior to 25.24.2 are vulnerable to OS command injection via crafted media file paths containing shell metacharacters, enabling arbitrary command execution with Node.js process privileges.
date: "2026-10-14T16:34:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:stills:stills:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - command-injection
  - rce
  - webserver
vendors:
  - Stills
products:
  - Stills (< 25.24.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Stills before 25.24.2 contains an OS command injection vulnerability that allows attackers to execute shell commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: Attackers can name a media file with $(...) or backticks to execute operating system commands with Node.js process privileges when ffmpeg, ffprobe, gifsicle, or convert runs.
    confidence_band: high
cves:
  - id: CVE-2026-110649
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110649
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Stills to version 25.24.2 or later to mitigate CVE-2026-110649.
      owner: IT Operations
      due: 24h
      evidence: Stills before 25.24.2 contains an OS command injection vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Stills to 25.24.2 or later.
      owner: IT Operations
      addresses: CVE-2026-110649
      evidence: Source NVD advisory.
---

Stills versions prior to 25.24.2 contain an OS command injection vulnerability that allows unauthenticated attackers to execute arbitrary commands on the underlying host. The vulnerability exists because the application improperly sanitizes file paths before passing them to external media processing utilities, specifically ffmpeg, ffprobe, gifsicle, and ImageMagick's convert. By creating or supplying media files with malicious paths containing shell metacharacters such as $(...) or backticks, an attacker can cause the host system to interpret these sequences as shell commands. Because these utilities are invoked by the application's runtime, the injected commands execute with the same privileges as the Node.js process. This flaw poses a significant risk to the integrity and availability of the hosting environment, as it facilitates remote code execution without the need for authentication.

## Attack Chain

1. Attacker identifies a target application utilizing Stills for media processing.
2. Attacker crafts a malicious filename or directory structure containing command injection metacharacters (e.g., `$(whoami).jpg` or `` `rm -rf /`.jpg ``).
3. Attacker uploads or causes the application to reference the malicious media file path.
4. The Stills application receives the path and fails to sanitize the shell metacharacters.
5. The application invokes a system utility (ffmpeg, ffprobe, gifsicle, or convert) using the unsanitized path as an argument.
6. The operating system shell interprets the metacharacters within the filename.
7. The injected shell command executes with the privileges of the Node.js process.
8. Attacker achieves remote code execution for potential data exfiltration or system compromise.

## Impact

Successful exploitation of this vulnerability allows for arbitrary command execution on the host server. This could lead to full system compromise, exfiltration of sensitive configuration data, or lateral movement within the environment. As the vulnerability allows command execution at the privilege level of the application process, it represents a critical risk to any infrastructure running an affected version of Stills.

## Recommendation

Prioritized actions for detection and remediation:

* Patch Stills by upgrading to version 25.24.2 or later immediately to address CVE-2026-110649.
* Audit application logs for abnormal filename patterns, specifically those containing shell metacharacters such as `$`, `(`, `)`, or backticks, in paths processed by ffmpeg, ffprobe, gifsicle, or convert.
* Ensure that the Node.js process running Stills operates with the least privilege necessary to limit the scope of impact if an injection vulnerability is exploited.
