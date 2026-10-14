---
title: OS Command Injection in nodejs-whisper
slug: 2026-10-nodejs-whisper-command-injection
description: The nodejs-whisper package through version 0.3.1 contains an OS command injection vulnerability in the convertToWavType() function that allows unauthenticated command execution via crafted audio file paths.
date: "2026-10-14T16:33:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:nodejs-whisper_project:nodejs-whisper:*:*:*:*:*:node.js:*:*
products:
  - nodejs-whisper (<= 0.3.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The package uses shelljs exec() to call ffmpeg, allowing command substitution via $() or quotes.
    confidence_band: high
cves:
  - id: CVE-2026-110644
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110644
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - AppSec
  immediate_actions:
    - action: Audit applications for nodejs-whisper usage
      owner: AppSec
      due: 24h
      evidence: Package is vulnerable up to 0.3.1
  mitigation_plan:
    - priority: immediate
      action: Remove or patch nodejs-whisper dependency
      owner: IT Operations
      addresses: CVE-2026-110644
      evidence: NVD vulnerability disclosure
---

The nodejs-whisper library, specifically versions 0.3.1 and earlier, contains a critical OS command injection vulnerability within the convertToWavType() function. This vulnerability arises because the package uses the shelljs exec() function to invoke the ffmpeg utility to process audio files. The library fails to sanitize user-supplied file paths, allowing an attacker to inject shell metacharacters such as command substitution ($()) or closing quotes into the command string. When an application utilizing nodejs-whisper processes a malicious input, the injected commands are executed by the underlying shell with the privileges of the Node.js process. This poses a significant risk to any server or environment running applications that accept user-provided audio files for processing via this library.

## Impact

Successful exploitation allows for arbitrary code execution on the host operating system. Depending on the privileges of the Node.js process, an attacker could achieve full system compromise, exfiltrate sensitive data, or move laterally within the network. This affects all applications relying on the vulnerable nodejs-whisper library for audio conversion tasks.

## Recommendation

* Immediately update the nodejs-whisper dependency to a patched version once available; as of this report, developers should move to a secure alternative or apply strict input validation.
* Audit all application code that utilizes nodejs-whisper to identify if audio file paths are sourced from untrusted user input.
* Implement input sanitization to ensure that file names do not contain shell metacharacters such as $, (), or quotes before they are passed to system-level commands.
* Monitor process execution logs for suspicious child processes spawned by Node.js applications, specifically looking for shells or utility commands like ffmpeg being invoked with shell metacharacters in arguments.
