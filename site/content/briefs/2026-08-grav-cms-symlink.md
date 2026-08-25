---
title: Arbitrary File Overwrite in Grav CMS via Symlink Following
slug: 2026-08-grav-cms-symlink
description: Grav CMS versions before 2.0.16 are vulnerable to arbitrary file overwrites via a symlink following flaw in the Scheduler component's lock file creation process.
date: "2026-08-25T04:06:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - cms
  - file-write
vendors:
  - Grav CMS
products:
  - Grav CMS (2.0.15)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation of Vulnerability
    evidence: Grav CMS before 2.0.16 contains a symlink following vulnerability in Scheduler Job::createLockFile()... that allows local attackers to overwrite arbitrary files
    confidence_band: high
cves:
  - id: CVE-2026-72696
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72696
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Grav CMS to 2.0.16
      owner: IT Operations
      addresses: CVE-2026-72696
      evidence: Grav CMS before 2.0.16 contains a symlink following vulnerability
---

Grav CMS versions prior to 2.0.16 contain a security flaw in the Scheduler Job::createLockFile() method, which fails to securely handle the creation of lock files in temporary directories. Because the application utilizes predictable file paths within world-writable directories for its locking mechanism, a local attacker can create a symbolic link at the expected lock file location. When the Grav CMS scheduler executes, it follows this symbolic link to the attacker-specified target and overwrites the target file with a job ID string. This vulnerability effectively allows an attacker with local user access to corrupt or overwrite any file accessible to the web server process, potentially leading to privilege escalation or service disruption depending on the targeted files.

## Impact

Successful exploitation allows local attackers to overwrite arbitrary files with the privileges of the web server user. This can be used to disable security controls, corrupt configuration files, or facilitate further system-level compromise. The vulnerability affects all Grav CMS installations prior to version 2.0.16.

## Recommendation

- Upgrade Grav CMS to version 2.0.16 or later immediately to address the insecure lock file handling in the Scheduler component.
- Review directory permissions on the host system to ensure that web-writable temporary directories are not world-writable, limiting the ability of local users to place arbitrary symlinks.
- Monitor logs for unusual file write activity originating from the web server user process, particularly within critical system directories.
