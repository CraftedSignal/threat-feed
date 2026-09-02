---
title: Command Injection Vulnerability in rpm rpmbuild
slug: 2026-09-rpm-command-injection
description: A command injection vulnerability (CVE-2026-84837) in the rpmbuild -t* functionality allows attackers to execute arbitrary commands by supplying malicious tarball filenames or paths in build workflows.
date: "2026-09-02T17:16:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rpm:rpm:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ci-cd
  - rpm
vendors:
  - RPM Software Management
products:
  - rpm
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: Successful exploitation allows for arbitrary command execution with the privileges of the build user.
    confidence_band: high
cves:
  - id: CVE-2026-84837
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84837
action_plan:
  priority: elevated
  owners:
    - DevOps
    - Security Engineering
  immediate_actions:
    - action: Audit CI/CD pipeline configurations for automated use of rpmbuild -t
      owner: DevOps
      due: 48h
      evidence: Source notes the vulnerability is relevant in automated build or CI workflows.
  mitigation_plan:
    - priority: immediate
      action: Patch rpm package when vendors release updates for CVE-2026-84837
      owner: IT Operations
      addresses: CVE-2026-84837
      evidence: NVD vulnerability disclosure
---

CVE-2026-84837 is a command injection vulnerability found in the rpm package manager, specifically affecting the `rpmbuild -t*` functionality. The vulnerability arises when the utility processes tarballs with filenames or paths containing shell metacharacters. If an automated build process or continuous integration (CI) pipeline accepts externally sourced or untrusted filenames, an attacker can craft a filename that breaks the command structure, leading to arbitrary code execution.

The impact of this vulnerability is significant in CI/CD environments where build systems often run with elevated privileges or have access to sensitive development secrets. Exploitation occurs during the build process, allowing the attacker to run commands under the context of the user executing the `rpmbuild` command. Defenders should audit automated build scripts that use `rpmbuild` to ensure inputs are sanitized and to assess whether they are currently processing untrusted or unverified tarball artifacts.

## Impact

Successful exploitation allows for arbitrary command execution with the privileges of the build user, leading to potential information disclosure of source code, theft of build credentials, or disruption of development and delivery pipelines. This flaw poses a high risk to automated environments processing third-party artifacts.

## Recommendation

- Identify all automated CI/CD pipelines and developer workstations utilizing `rpmbuild -t`.
- Audit build scripts to determine if filenames or paths processed by `rpmbuild` are derived from user-controlled or external, untrusted sources.
- Apply security patches for rpm provided by distribution vendors as they become available to remediate CVE-2026-84837.
- Implement strict input validation and sanitization for all file artifacts passed to build utilities in CI/CD pipelines.
