---
title: OS Command Injection in SadTalker via Filename Interpolation
slug: 2026-09-sadtalker-rce
description: SadTalker is vulnerable to OS command injection due to improper neutralization of shell metacharacters in uploaded audio filenames during the video muxing process.
date: "2026-09-04T15:26:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:opentalker:sadtalker:*:*:*:*:*:*:*:*
vendors:
  - OpenTalker
products:
  - SadTalker
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can upload audio files with shell metacharacters in the filename to break out of quoted arguments and execute arbitrary system commands when video generation occurs.
    confidence_band: high
cves:
  - id: CVE-2026-85696
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85696
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit environment for deployments of SadTalker
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-85696 affects SadTalker
  mitigation_plan:
    - priority: immediate
      action: Upgrade SadTalker to a patched version once released by OpenTalker
      owner: IT Operations
      addresses: CVE-2026-85696
      evidence: CVE-2026-85696 vulnerability report
---

SadTalker contains an OS command injection vulnerability (CVE-2026-85696) within its video muxing process. The vulnerability occurs because uploaded audio filenames are directly interpolated into system shell commands (specifically calls to ffmpeg) without appropriate sanitization or escaping. By providing a crafted filename containing shell metacharacters, an unauthenticated attacker can escape the intended shell arguments and execute arbitrary commands on the host operating system with the privileges of the application process. Given that ffmpeg is a standard dependency for video processing, this flaw impacts deployments of SadTalker on any host operating system. Defenders should prioritize identifying instances of this software and ensuring user-supplied filenames are treated as untrusted input.

## Impact

Successful exploitation of this vulnerability allows for unauthenticated remote code execution on the server running the SadTalker application. This can lead to full system compromise, data exfiltration, or the installation of persistent malicious payloads.

## Recommendation

- Implement strict input validation on all user-supplied filenames before passing them to system calls or external binaries.
- Apply the vendor-provided security patch or upgrade to the version that remediates CVE-2026-85696 as soon as it becomes available.
- Review web application logs for POST requests containing unusual characters such as semicolons, ampersands, or pipe operators within file upload parameters.
- Run the application in a hardened container with minimal filesystem permissions to limit the scope of potential command execution.
