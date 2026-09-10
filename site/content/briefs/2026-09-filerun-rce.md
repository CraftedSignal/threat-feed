---
title: OS Command Injection in FileRun
slug: 2026-09-filerun-rce
description: FileRun versions prior to 2026.3.0 contain an OS command injection vulnerability via an improper redefinition of escapeshellcmd() that allows unauthenticated or authenticated users to execute arbitrary commands.
date: "2026-09-10T19:07:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:filerun:filerun:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - rce
  - file-run
vendors:
  - FileRun
products:
  - FileRun (< 2026.3.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: FileRun before 2026.3.0 contains an OS command injection vulnerability caused by a no-op redefinition of escapeshellcmd() in CLI.php that strips shell-metacharacter escaping.
    confidence_band: high
cves:
  - id: CVE-2026-73694
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73694
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade FileRun to version 2026.3.0 or later
      owner: IT Operations
      due: 48h
      evidence: Source explicitly identifies version 2026.3.0 as the remediation.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 2026.3.0
      owner: IT Operations
      addresses: CVE-2026-73694
      evidence: NVD vulnerability notice.
---

FileRun versions prior to 2026.3.0 are susceptible to OS command injection due to the insecure redefinition of the PHP function 'escapeshellcmd()' within the 'CLI.php' file. This flaw effectively disables necessary character escaping for shell metacharacters, permitting unsanitized user input to reach an 'exec()' sink. The vulnerability presents two primary attack vectors: an interactive path requiring superuser privileges via 'image_preview.php' using the 'args' parameter, and a persistent vector where malicious payloads are injected into 'thumbnails_ffmpeg_args' or 'thumbnails_ffmpeg_ss'. In the latter scenario, the attacker-controlled code is executed whenever a user triggers the video thumbnail generation process, potentially leading to unauthorized system access or remote code execution.

## Impact

Successful exploitation allows for remote code execution on the server hosting the FileRun instance. Depending on the privileges of the web service account, this could lead to full system compromise, exfiltration of stored user data, or lateral movement within the environment.

## Recommendation

Update FileRun to version 2026.3.0 or later immediately to patch the command injection vulnerability in CLI.php.

## Impact

The vulnerability is rated with a CVSS v3.1 base score of 7.2. Organizations utilizing FileRun are at risk of remote code execution, which could result in unauthorized data access or full server takeover.
