---
title: CodeIgniter Path Traversal via UploadedFile::move()
slug: 2026-08-codeigniter-path-traversal
description: CodeIgniter Framework versions prior to 4.7.4 contain a path traversal vulnerability in the UploadedFile::move() method that allows attackers to write files to arbitrary filesystem locations when unsanitized client filenames are processed.
date: "2026-08-07T21:31:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - path-traversal
  - codeigniter
vendors:
  - CodeIgniter
products:
  - CodeIgniter Framework
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can supply a filename containing path traversal sequences (e.g. ../../public/shell.php) to write uploaded content outside the intended upload directory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Depending on the destination path and server configuration, an attacker can supply a filename containing path traversal sequences to write uploaded content outside the intended upload directory.
    confidence_band: med
cves:
  - id: CVE-2026-63222
    cvss: 7.5
    epss: 0.0045
references:
  - https://github.com/advisories/GHSA-hhmc-q9hp-r662
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63222
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade CodeIgniter Framework to 4.7.4
      owner: IT Operations
      due: 48h
      evidence: 'Source states: Upgrade to v4.7.4 or later.'
  mitigation_plan:
    - priority: immediate
      action: Apply code-level sanitization using sanitize_filename() or getRandomName() for file uploads
      owner: Application Security
      addresses: CVE-2026-63222
      evidence: Source provides specific helper functions to sanitize or randomize names.
---

CodeIgniter Framework versions prior to 4.7.4 are susceptible to a path traversal vulnerability tracked as CVE-2026-63222. The vulnerability exists within the `UploadedFile::move()` method. When this method is invoked without a second argument, the framework defaults to using the original filename provided by the client without performing necessary sanitization.

An attacker can exploit this by crafting a malicious filename containing path traversal sequences, such as "../../", to escape the intended upload directory and overwrite or create files elsewhere on the server. If the application is configured to allow direct execution of uploaded content, this flaw could be leveraged to gain remote code execution. It is critical to note that the patch introduced in version 4.7.4 only mitigates the issue when the method is used without a second argument. Applications that explicitly pass user-provided filenames to the second argument of `move()` remain vulnerable unless developers implement explicit sanitization logic.

## Impact

Successful exploitation allows for arbitrary file write on the host server. This could lead to the overwriting of sensitive configuration files, the placement of web shells in public directories, or the corruption of system files, potentially leading to full system compromise depending on web server permissions and file system structure.

## Recommendation

- Upgrade to CodeIgniter Framework v4.7.4 or later immediately.
- If upgrading is not feasible, implement a workaround by using `getRandomName()` for destination files or by explicitly sanitizing any user-provided filenames using `sanitize_filename()` before passing them to the `move()` method.
- Audit application code for instances where `UploadedFile::move()` is called with a second argument derived from `$file->getName()` or `$file->getClientName()` and ensure these are properly validated.
