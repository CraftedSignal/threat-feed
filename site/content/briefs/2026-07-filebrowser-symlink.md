---
title: File Browser Symlink Following Vulnerability Allows Out-of-Scope File Deletion (CVE-2026-55667)
slug: 2026-07-filebrowser-symlink
description: A File Browser user with only `Create` permission can exploit CVE-2026-55667, an incomplete fix for CVE-2026-54094, to delete arbitrary files and directories outside their authorized scope by abusing the `ScopedFs.RemoveAll` function's symlink-following behavior during failed upload cleanup, leading to data loss, cross-tenant data deletion, or denial of service.
date: "2026-07-20T21:23:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - file-browser
  - symlink-attack
  - data-loss
  - denial-of-service
vendors:
  - filebrowser
products:
  - filebrowser (<= 2.63.15)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: A per-tenant / per-share scoped user with only Create can destroy any file the File Browser process can reach via a symlink lexically inside their scope
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: full-instance DoS (delete the database dir → all users/shares/config gone, admin login fails)
    confidence_band: high
cves:
  - id: CVE-2026-55667
    cvss: 8.2
    epss: 0.00359
  - id: CVE-2026-54094
    cvss: 7.5
    epss: 0.0046
references:
  - https://github.com/advisories/GHSA-fmm7-x4gx-8jhr
  - CVE-2026-55667
  - CVE-2026-54094
---

A critical vulnerability, tracked as CVE-2026-55667, has been identified in File Browser versions up to 2.63.15, allowing a non-admin user with only `Create` permissions to delete arbitrary files and directories outside their designated scope. This flaw is an incomplete fix for CVE-2026-54094 and stems from the `ScopedFs.RemoveAll` function's failure to properly guard against symlink following during the cleanup process for failed uploads. Attackers can leverage a pre-existing, out-of-band planted symlink within their scope to trick the application into deleting sensitive files, potentially including other tenants' data or the application's own database. This can lead to data integrity compromises, cross-tenant data deletion, and a full denial of service for the File Browser instance. The vulnerability affects instances deployed on Linux-based systems where symlink creation and following are possible.

## Attack Chain

1. **Precondition Fulfillment**: An attacker ensures an escaping directory symlink (e.g., `/scope/link` pointing to `/out-of-scope`) is present within the user's File Browser scope. This symlink must be planted out-of-band as File Browser offers no symlink creation API.
2. **Initial Access**: The attacker obtains authenticated access as a non-admin File Browser user with `Perm.Create=true` enabled and `Perm.Delete=false` (delete permission is not required for exploitation).
3. **Malicious Request**: The attacker sends an HTTP POST request to the File Browser `/api/resources` endpoint, attempting to "upload" a file to a path under the controlled symlink (e.g., `POST /api/resources/link/victim.txt`).
4. **Containment Bypass Attempt**: File Browser's `resourcePostHandler` attempts to process the upload. The initial file info validation (`NewFileInfo`) for the out-of-scope target fails, and the subsequent `writeFile` operation is correctly blocked by `ScopedFs` containment, resulting in a 403 HTTP response.
5. **Failure-Cleanup Trigger**: Due to the failed write, the `resourcePostHandler` triggers an internal cleanup routine at `http/resource.go:173`, which calls `d.user.Fs.RemoveAll(r.URL.Path)` on the user-controlled, unvalidated path (`/link/victim.txt`).
6. **Symlink Dereference and Deletion**: The `ScopedFs.RemoveAll` function, which uniquely lacks the necessary `guard()` mechanism unlike other methods, dereferences the pre-existing symlink (e.g., `/link` pointing to `/tmp/fb-out`).
7. **Impact Achieved**: The `RemoveAll` function proceeds to delete the target file (e.g., `/tmp/fb-out/victim.txt`) or recursively delete contents if the target is a directory, leading to data loss or denial of service.

## Impact

Successful exploitation of CVE-2026-55667 allows an authenticated File Browser user with only `Create` permissions to destroy any file or directory that the File Browser process has access to, provided an escaping symlink exists within their scope. This leads to severe consequences such as data integrity loss, cross-tenant data deletion in multi-tenant environments, and full denial of service if the application's database directory is targeted. The vulnerability bypasses both the `ScopedFs` boundary designed to contain user actions and the `Perm.Delete` gate, enabling low-privileged users to perform high-privileged destructive operations.

## Recommendation

* Patch CVE-2026-55667 by upgrading File Browser to a version greater than 2.63.15, which addresses the incomplete fix of CVE-2026-54094.
* Regularly review file system permissions for the File Browser process to ensure it operates with the principle of least privilege, reducing the blast radius of potential exploits.
* Ensure robust backup and recovery procedures are in place for File Browser data and any managed files to mitigate the impact of data deletion.
