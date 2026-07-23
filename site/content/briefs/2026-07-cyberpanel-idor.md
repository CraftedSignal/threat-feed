---
title: CyberPanel Insecure Direct Object Reference (IDOR) Vulnerability (CVE-2026-65917)
slug: 2026-07-cyberpanel-idor
description: An Insecure Direct Object Reference (IDOR) vulnerability, tracked as CVE-2026-65917, exists in CyberPanel versions through 1.9.1, specifically within the IncBackups application's incremental-backup handlers, allowing authenticated panel users to exploit attacker-controlled IncJob integer IDs to access, read metadata from, delete, or trigger unauthorized restoration of other tenants' backup resources, potentially leading to operations with root privileges.
date: "2026-07-23T16:22:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - idor
  - web-panel
  - privilege-escalation
  - data-manipulation
  - cyberpanel
vendors:
  - CyberPanel
products:
  - CyberPanel (through 1.9.1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Exploiting the restoration feature can lead to operations with root privileges.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: irrecoverably delete another tenant's backup snapshots
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: access or manipulate other tenants' backup resources by supplying an attacker-controlled globally sequential IncJob integer ID that is never re-scoped to the authorized domain. Attackers can enumerate sequential backup IDs to read another tenant's backup metadata
    confidence_band: med
cves:
  - id: CVE-2026-65917
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65917
---

A critical Insecure Direct Object Reference (IDOR) vulnerability, identified as CVE-2026-65917, affects CyberPanel versions up to and including 1.9.1. This flaw resides within the IncBackups application's incremental-backup handlers, specifically in the `deleteBackup`, `fetchRestorePoints`, and `restorePoint` functions. Authenticated CyberPanel users can exploit this by manipulating a globally sequential `IncJob` integer ID, which is not properly re-scoped to the authorized domain. This oversight allows attackers to access or manipulate backup resources belonging to other tenants. The vulnerability enables actions such as enumerating sequential backup IDs to read another tenant's backup metadata, irreversibly deleting backup snapshots, or initiating unauthorized restoration of another tenant's backup job with elevated root privileges. This vulnerability poses a significant risk of data compromise, destruction, and unauthorized system access across multi-tenant CyberPanel deployments. The issue was fixed in commit b198460.

## Attack Chain

1. An authenticated attacker gains access to a CyberPanel instance.
2. The attacker identifies the vulnerable `IncBackups` application's incremental-backup handlers (e.g., `deleteBackup`, `fetchRestorePoints`, `restorePoint`).
3. The attacker observes or infers the globally sequential nature of `IncJob` integer IDs used to reference backup resources.
4. The attacker crafts a request to one of the vulnerable handlers, supplying a manipulated `IncJob` integer ID corresponding to another tenant's backup resource.
5. Depending on the handler targeted, the attacker can:
 a. Read sensitive backup metadata from another tenant's account via `fetchRestorePoints`.
 b. Irreversibly delete another tenant's backup snapshots via `deleteBackup`.
 c. Trigger an unauthorized restoration of another tenant's backup job via `restorePoint`.
6. If the attacker initiates a restoration, the operation is executed with root privileges, potentially leading to system compromise or data overwrites on the victim tenant's environment.

## Impact

Successful exploitation of CVE-2026-65917 allows an authenticated user to gain unauthorized access to, delete, or restore backup resources belonging to other tenants on the same CyberPanel instance. This can lead to severe data breaches, complete data loss for affected tenants due to irreversible deletion of backups, or unauthorized system takeover through malicious restoration processes executing with root privileges. The vulnerability directly impacts data confidentiality, integrity, and availability for all tenants hosted on a vulnerable CyberPanel server. While no specific victim count or targeted sectors are provided, any organization utilizing CyberPanel through version 1.9.1 in a multi-tenant environment is at risk.

## Recommendation

* Immediately patch CyberPanel instances to a version that includes commit b198460 or later to address CVE-2026-65917.
* Review web server logs for unusual access patterns to the `IncBackups` application endpoints, especially requests containing sequential or non-user-specific `IncJob` integer IDs, which may indicate attempted exploitation of CVE-2026-65917.
* Monitor for unauthorized backup deletion or restoration events within CyberPanel's activity logs.
