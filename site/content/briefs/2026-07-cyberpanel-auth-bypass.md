---
title: CyberPanel Missing Authorization Vulnerability Allows Cross-Tenant Backup Manipulation
slug: 2026-07-cyberpanel-auth-bypass
description: A missing authorization vulnerability, identified as CVE-2026-65916, in CyberPanel through version 1.9.1 allows authenticated users to manipulate and destroy other tenants' backups by sending crafted POST requests to the `cancelBackupCreation` handler.
date: "2026-07-23T16:19:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - authorization-bypass
  - data-destruction
  - cyberpanel
  - cve
vendors:
  - usmannasir
products:
  - CyberPanel (through 1.9.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Attackers can send crafted POST requests with arbitrary backupCancellationDomain and fileName parameters to terminate backup processes, delete backup archives, corrupt backup status files, and remove database records belonging to other tenants.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Stolen Data
    evidence: Attackers can send crafted POST requests with arbitrary backupCancellationDomain and fileName parameters to terminate backup processes, delete backup archives, corrupt backup status files, and remove database records belonging to other tenants.
    confidence_band: high
cves:
  - id: CVE-2026-65916
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65916
  - https://github.com/usmannasir/cyberpanel/commit/b1984603f9b0099b39bca46fea176e53b6d4d601
  - https://github.com/usmannasir/cyberpanel/issues/1829
  - https://www.vulncheck.com/advisories/cyberpanel-missing-authorization-in-cancelbackupcreation-handler
rules:
  - title: Detects CVE-2026-65916 Exploitation - CyberPanel Missing Authorization
    description: Detects exploitation attempts of CVE-2026-65916, a missing authorization vulnerability in CyberPanel's cancelBackupCreation handler, by identifying POST requests to the affected endpoint with specific parameters.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
      - T1565.002
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-65916 describes a critical missing authorization vulnerability affecting CyberPanel installations up to version 1.9.1. This flaw, fixed in commit `b198460`, resides within the `cancelBackupCreation` handler, which is intended to manage backup processes. However, due to insufficient authorization checks, any authenticated user can exploit this vulnerability to impact backups belonging to other tenants on the same CyberPanel instance. By sending specially crafted POST requests containing arbitrary `backupCancellationDomain` and `fileName` parameters, attackers can terminate backup processes, delete existing backup archives, corrupt backup status files, and remove corresponding database records for other users. This poses a significant risk of data loss and service disruption for multi-tenant CyberPanel environments.

## Attack Chain

1. An attacker obtains valid authentication credentials for a low-privileged account on a CyberPanel instance.
2. The attacker crafts an HTTP POST request targeting the `/cancelBackupCreation` endpoint of the CyberPanel web interface.
3. The crafted request includes parameters `backupCancellationDomain` and `fileName`, specifying a target domain and backup file belonging to another tenant.
4. The CyberPanel application, due to the missing authorization check, processes the request without verifying if the authenticated user has rights to manage backups for the specified `backupCancellationDomain`.
5. The `cancelBackupCreation` handler executes internal commands to stop, delete, or corrupt the backup process or files associated with the targeted tenant.
6. The targeted tenant's backup processes are terminated, their backup archives are deleted, their backup status files become corrupted, and related database records are removed.
7. This results in significant data loss, unavailability of critical backups, and potential service disruption for the victim tenant.

## Impact

The successful exploitation of CVE-2026-65916 can lead to severe consequences, primarily data loss and data unavailability for tenants sharing a CyberPanel installation. Attackers can completely destroy critical backup archives, making recovery from other incidents impossible. This directly impacts data integrity and availability, leading to potential business continuity failures, reputational damage, and financial losses for affected organizations. The vulnerability affects multi-tenant environments where one authenticated user can maliciously impact others.

## Recommendation

* Patch CVE-2026-65916 by upgrading CyberPanel to a version that includes commit `b198460` or later immediately.
* Deploy the provided Sigma rule to your SIEM to detect attempts to exploit the `cancelBackupCreation` handler.
* Monitor `webserver` logs for suspicious POST requests to the `/cancelBackupCreation` endpoint, especially those originating from unexpected accounts or specifying domains not owned by the requesting user.
