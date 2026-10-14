---
title: CVE-2026-110645 OS Command Injection in Video-stitch
slug: 2026-10-video-stitch-command-injection
description: Video-stitch versions prior to 2.0.0-beta.1 contain an OS command injection vulnerability allowing attackers to achieve remote code execution by injecting shell metacharacters into file name parameters processed by ffmpeg.
date: "2026-10-14T16:34:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:video-stitch:video-stitch:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - command-injection
vendors:
  - Video-stitch
products:
  - Video-stitch (< 2.0.0-beta.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers who influence file names passed to concat(), cut(), or merge() can inject shell metacharacters to run commands with the Node.js process privileges.
    confidence_band: high
cves:
  - id: CVE-2026-110645
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110645
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Video-stitch to 2.0.0-beta.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in versions before 2.0.0-beta.1
  mitigation_plan:
    - priority: immediate
      action: Upgrade Video-stitch library to 2.0.0-beta.1 or later
      owner: IT Operations
      addresses: CVE-2026-110645
      evidence: NVD vulnerability data
---

Video-stitch before version 2.0.0-beta.1 is vulnerable to an OS command injection flaw arising from insecure handling of input parameters. The vulnerability occurs because file names are interpolated directly into shell-executed ffmpeg command lines without proper quoting or sanitization. An attacker who can influence the input provided to the concat(), cut(), or merge() functions in the application can inject arbitrary shell metacharacters. This flaw allows the execution of operating system commands with the permissions of the underlying Node.js process. This vulnerability is highly critical as it provides a direct path for remote code execution (RCE) in any environment using affected versions of Video-stitch to process user-supplied media files.

## Impact

Successful exploitation allows for full system command execution under the context of the Node.js process. This may lead to complete compromise of the hosting server, unauthorized access to sensitive files, or further lateral movement within the network. The scope of impact is limited to applications integrating the vulnerable Video-stitch library.

## Recommendation

- Upgrade the Video-stitch library to version 2.0.0-beta.1 or later immediately.
- Implement strict input validation and sanitization for all file names or parameters passed to the concat(), cut(), and merge() functions within the application layer.
- Apply the principle of least privilege to the service account running the Node.js application to limit the potential impact of a successful command injection.
