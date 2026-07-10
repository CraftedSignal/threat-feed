---
title: Froxlor DataDump.add() Incomplete Symlink Validation Allows Arbitrary Directory Ownership Takeover
slug: 2024-01-froxlor-symlink-takeover
description: Froxlor versions before 2.3.6 are vulnerable to arbitrary directory ownership takeover via the DataDump.add() function due to incomplete symlink validation, allowing attackers to manipulate file ownership via a malicious symlink.
date: "2024-01-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - froxlor
  - symlink
  - privilege-escalation
vendors:
  - Froxlor
products:
  - Froxlor
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2023-6069
    cvss: 9.9
    epss: 0.0025
references:
  - https://github.com/advisories/GHSA-75h4-c557-j89r
rules:
  - title: Froxlor DataDump API Call with Suspicious Path
    description: Detects API calls to DataDump.add with a path containing '..', potentially indicating path traversal, or a path starting with '/'
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548.001
    data_sources:
      - webserver
      - linux
  - title: Froxlor Suspicious chown Execution
    description: Detects chown command executed by root or a user that runs Froxlor cron jobs with suspicious arguments
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Froxlor, a server management panel, is vulnerable to an arbitrary directory ownership takeover in versions prior to 2.3.6. The vulnerability stems from an incomplete fix for CVE-2023-6069 related to symlink validation. Specifically, the `DataDump.add()` function lacks the `$fixed_homedir` parameter in its call to `FileDir::makeCorrectDir()`, which is present in other customer-facing API commands. This oversight allows a malicious customer to create a symlink within their web directory that points to an arbitrary directory on the system. When the `ExportCron` task runs as root, it executes `chown -R` on the resolved symlink target, effectively changing the ownership of the target directory and its contents to the attacker's user ID and group ID. This can lead to horizontal and vertical privilege escalation, data breaches, and service disruptions. The vulnerability can be triggered via a single API call, and the impact is delayed until the next cron run (typically hourly).

## Attack Chain

1.  Attacker creates a symlink within their web directory (accessible via FTP/SSH) pointing to a target directory (e.g., `/var/customers/webs/victim_customer` or `/etc`). For example: `ln -s /var/customers/webs/victim_customer /var/customers/webs/attacker_customer/steal`.
2.  Attacker crafts an API request to `DataDump.add()` specifying the path to the created symlink (e.g., `"path":"steal"`).
3.  The `DataDump.add()` function, located in `DataDump.php`, calls `FileDir::makeCorrectDir()` without the `$fixed_homedir` parameter, bypassing symlink validation.
4.  The API call schedules a `CREATE_CUSTOMER_DATADUMP` task via `Cronjob::inserttask()`, including the unvalidated path as `destdir` in the task data.
5.  The `ExportCron::handle()` function executes periodically as root, processing the scheduled data dump tasks.
6.  The `ExportCron` executes a series of commands including `mkdir -p`, `tar cfz`, and `chown -R` with the attacker-controlled `destdir` path.
7.  The `chown -R` command, executed via `FileDir::safe_exec()`, resolves the symlink and recursively changes the ownership of the target directory to the attacker's UID and GID.
8.  The attacker now owns the target directory and can modify files, escalate privileges, or disrupt services.

## Impact

This vulnerability can have severe consequences: A malicious customer can take ownership of other customer's web files, databases, and email data, leading to data breaches. By targeting system directories like `/etc`, they can gain root access by modifying system files like `/etc/passwd` and `/etc/shadow`. This can lead to full system compromise. The attack requires minimal effort and can be difficult to trace due to the delayed impact. Successful exploitation leads to full read/write access to all files in the targeted directory, as well as potential service disruption.

## Recommendation

*   Apply the patch provided by Froxlor in version 2.3.6, which corrects the call to `FileDir::makeCorrectDir()` in `DataDump.add()` to include the `$fixed_homedir` parameter (see fix in advisory).
*   Deploy the "Froxlor DataDump API Call with Suspicious Path" Sigma rule to detect API calls to `DataDump.add()` with potentially malicious paths in web server logs.
*   Implement the suggested fix in `ExportCron.php` to check if the destination path is a symlink before executing `chown -R` (see fix in advisory).
*   Monitor process creation events for the execution of `chown -R` by the root user or the user running the Froxlor cron jobs, with a destination path that may indicate a symlink using the "Froxlor Suspicious chown Execution" Sigma rule.
