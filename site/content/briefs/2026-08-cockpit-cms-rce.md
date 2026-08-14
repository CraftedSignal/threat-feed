---
title: Command Injection in Cockpit CMS FFmpeg Integration
slug: 2026-08-cockpit-cms-rce
description: Cockpit CMS versions 2.14.0 and prior are vulnerable to authenticated command injection via malicious filenames processed by the FFmpeg integration.
date: "2026-08-14T22:14:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - remote-code-execution
  - injection
  - cockpit-cms
vendors:
  - Cockpit CMS
products:
  - Cockpit CMS (<= 2.14.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The vulnerability allows authenticated users to execute arbitrary commands by uploading a video file with a shell metacharacter-laden filename.
    confidence_band: high
cves:
  - id: CVE-2026-73680
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73680
rules:
  - title: Detect CVE-2026-73680 Exploitation - Command Injection via Filename
    description: Detects potential command injection attempts by identifying shell metacharacters in uploaded filenames during a POST request to Cockpit CMS upload endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit environment for Cockpit CMS instances and confirm version.
      owner: SOC
      due: 24h
      evidence: CVE-2026-73680 affects Cockpit CMS 2.14.0 and prior.
  mitigation_plan:
    - priority: immediate
      action: Patch Cockpit CMS to the latest version.
      owner: IT Operations
      addresses: CVE-2026-73680
      evidence: NVD vulnerability entry.
---

Cockpit CMS version 2.14.0 and prior contains a command injection vulnerability within its FFmpeg-based video processing integration. The vulnerability occurs because the application passes a user-supplied filename directly to `Process::fromShellCommandline()` before applying its `slugify()` sanitization logic. 

An authenticated user possessing the `assets/upload` permission can exploit this by uploading a video file containing shell metacharacters (e.g., backticks, `$()`, or semicolons) within its filename. The underlying shell interprets these characters as command separators or subcommands, allowing the attacker to execute arbitrary commands with the privileges of the web-server user. This vulnerability represents a critical risk for deployments where untrusted users are granted file upload capabilities, as it provides a direct path to remote code execution (RCE) on the host server. Defenders should identify instances of Cockpit CMS and restrict access to the file upload functionality until the software can be patched.

## Attack Chain

1. Attacker authenticates to the Cockpit CMS application using valid credentials with `assets/upload` permissions.
2. Attacker crafts a video file name containing shell-breaking metacharacters (e.g., `test.mp4;id.mp4` or `$(whoami).mp4`).
3. Attacker initiates a file upload request through the Cockpit CMS dashboard or API for the asset management module.
4. The application receives the upload and invokes the FFmpeg integration component to process the video.
5. The integration logic fails to sanitize the filename before passing it to `Process::fromShellCommandline()`.
6. The system shell parses the injected characters, treating the filename suffix as an independent command.
7. The OS executes the injected command with the UID of the web-server process (e.g., `www-data` or `apache`).
8. Final objective achieved: remote command execution enabling persistence, further lateral movement, or data exfiltration from the web server.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary system commands on the host server. This could lead to a full system compromise, unauthorized access to sensitive application data, or pivoting into the internal network. The vulnerability impacts any organization running Cockpit CMS version 2.14.0 or earlier.

## Recommendation

- Upgrade Cockpit CMS to a version beyond 2.14.0 that implements input sanitization prior to process invocation.
- Review and restrict user accounts with `assets/upload` permissions to minimize the attack surface.
- Audit webserver error and access logs for requests containing shell metacharacters in filenames, specifically looking for unusual patterns in POST requests to asset upload endpoints.
- Deploy WAF rules to inspect and block file upload parameters containing characters like `;`, `` ` ``, `$`, or `|` when processed by web-based CMS upload controllers.
