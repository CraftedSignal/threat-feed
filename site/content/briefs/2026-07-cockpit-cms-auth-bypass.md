---
title: Cockpit CMS Missing Authorization Vulnerability in Bucket File Storage API (CVE-2026-57855)
slug: 2026-07-cockpit-cms-auth-bypass
description: A missing authorization vulnerability, CVE-2026-57855, in the Cockpit CMS Bucket file storage API allows any authenticated user, regardless of their assigned role, to perform all file operations on any named bucket, including those designated for administrative use, potentially leading to privilege escalation, data manipulation, or data destruction.
date: "2026-07-13T23:18:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - web-application
  - cms
  - authorization-bypass
  - privilege-escalation
vendors:
  - Cockpit HQ
products:
  - Cockpit CMS < 2.14.0
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Any authenticated user, regardless of role, can perform all bucket operations on any named bucket, including buckets intended for admin use only.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Any authenticated user, regardless of role, can perform all bucket operations on any named bucket.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: The api() method in modules/System/Controller/Buckets.php executes bucket commands (ls, upload, removefiles, rename, createfolder) without performing any ACL or role check.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: The api() method in modules/System/Controller/Buckets.php executes bucket commands (ls, upload, removefiles, rename, createfolder) without performing any ACL or role check. Any authenticated user, regardless of role, can perform all bucket operations on any named bucket.
    confidence_band: high
cves:
  - id: CVE-2026-57855
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57855
  - https://gist.github.com/sermikr0/821c4edd3c34e98a62a50b07707785bd
  - https://github.com/Cockpit-HQ/Cockpit/commit/dde2d1d74f5f4e11de42a298918ea8c9684f932c
  - https://github.com/cockpit-hq/cockpit
  - https://www.vulncheck.com/advisories/cockpit-cms-missing-authorization-in-bucket-file-storage-api
---

CVE-2026-57855 describes a critical missing authorization vulnerability within the Cockpit CMS Bucket file storage API. Specifically, the `api()` method located in `modules/System/Controller/Buckets.php` fails to implement proper Access Control List (ACL) or role-based checks before executing various bucket commands such as `ls`, `upload`, `removefiles`, `rename`, and `createfolder`. This flaw enables any authenticated user, even those with low privileges, to bypass intended security restrictions and perform arbitrary file operations on any named bucket, including sensitive administrative buckets. The vulnerability, discovered by VulnCheck, has a CVSS v3.1 base score of 8.8, indicating a high potential for impact. If exploited, an attacker could gain unauthorized access to data, manipulate website content, delete critical files, or potentially achieve remote code execution by uploading malicious scripts into web-accessible directories, thereby escalating their privileges within the CMS environment.

## Attack Chain

1. An adversary obtains valid but low-privileged credentials for a Cockpit CMS instance.
2. The adversary authenticates to the Cockpit CMS web interface or directly interacts with its API.
3. The adversary crafts an HTTP request targeting the `/system/buckets/api` endpoint.
4. The request includes a bucket operation command (e.g., `upload`, `removefiles`, `createfolder`) and specifies a target bucket, potentially an administrator-only bucket.
5. The `api()` method in `modules/System/Controller/Buckets.php` processes the request and executes the command.
6. Due to the missing authorization checks, the system fails to verify the user's role or permissions for the requested operation or target bucket.
7. The command is executed successfully, allowing the adversary to perform unauthorized actions such as uploading web shells, deleting critical site files, or modifying configuration data.
8. This leads to privilege escalation, data destruction, data manipulation, or potentially arbitrary code execution on the Cockpit CMS server.

## Impact

Successful exploitation of CVE-2026-57855 can lead to severe consequences for organizations utilizing Cockpit CMS. The primary impact is unauthorized access to and manipulation of sensitive data. Attackers can upload malicious files, leading to potential website defacement or arbitrary code execution if a web shell is deployed. Furthermore, adversaries can delete or rename critical system files, causing denial of service, data loss, or inhibiting system recovery. The vulnerability also facilitates privilege escalation, allowing low-privileged authenticated users to gain administrative capabilities, take full control of the CMS, and potentially pivot to other systems within the network. While no specific victim count or targeted sectors are provided, any organization running affected versions of Cockpit CMS is at risk.

## Recommendation

* Patch Cockpit CMS instances to version 2.14.0 or newer immediately to address CVE-2026-57855, as indicated by the fix in `https://github.com/Cockpit-HQ/Cockpit/commit/dde2d1d74f5f4e11de42a298918ea8c9684f932c`.
* Implement robust monitoring of web server logs for suspicious activity directed at the `/system/buckets/api` endpoint, particularly for requests originating from low-privileged user accounts.
* Monitor file system integrity and changes within Cockpit CMS installation directories and associated bucket storage locations for unauthorized file uploads, deletions, or modifications.
* Regularly review user accounts and their assigned roles within Cockpit CMS to ensure the principle of least privilege is strictly enforced.
