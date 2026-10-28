---
brief_id: brief-2026-10-28-samba-vfs-ceph-rgw-bypass
event_id: brief-2026-10-28-samba-vfs-ceph-rgw-bypass
revision: 1
activity_at: "2026-10-28T20:39:14Z"
title: 'Samba: Access control bypass in vfs_ceph_rgw module (CVE-2026-109411)'
slug: 2026-10-samba-vfs-ceph-rgw-bypass
description: An access control bypass vulnerability in the Samba vfs_ceph_rgw module allows an authenticated attacker to read or overwrite restricted files via case-mismatched file lookups.
date: "2026-10-28T20:39:14Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source verified; no concrete IOCs or log artifacts provided for rule generation; hunt leads established.
cpes:
  - cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*
vendors:
  - Samba
products:
  - Samba (vfs_ceph_rgw module enabled)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: As a result, the server skips standard permission checks on the existing file, allowing the attacker to access or overwrite sensitive data owned by other users.
    confidence_band: high
cves:
  - id: CVE-2026-109411
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109411
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify all Samba shares utilizing the experimental vfs_ceph_rgw module.
      owner: IT Operations
      due: 24h
      evidence: An authenticated user can bypass access controls to read or overwrite restricted files on shares configured with the experimental vfs_ceph_rgw module.
  hunt_leads:
    - lead: Monitor for repeated file access failures or anomalous write attempts targeting the same directory path using varied character casing.
      technique_id: T1068
      data_needed:
        - Samba vfs audit logs
        - Linux file system access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: When a client requests an existing file using mismatched character casing, the module fails to perform a case-insensitive lookup correctly, causing the server to treat the operation as creating a new file.
  mitigation_plan:
    - priority: immediate
      action: Disable the vfs_ceph_rgw module in smb.conf configurations.
      owner: IT Operations
      addresses: CVE-2026-109411
      evidence: An authenticated user can bypass access controls to read or overwrite restricted files on shares configured with the experimental vfs_ceph_rgw module.
---

CVE-2026-109411 is an access control bypass vulnerability located in the `openat()` function of Samba's experimental `vfs_ceph_rgw` module. An authenticated attacker can exploit the module's failure to correctly handle case-insensitive file lookups. By requesting an existing file with mismatched character casing, the module bypasses standard permission checks, treating the request as a new file creation. This allows the attacker to read or overwrite files that would otherwise be restricted.

## Impact

Authenticated attackers with access to a share configured with the `vfs_ceph_rgw` module can read or overwrite sensitive files owned by other users, leading to potential data exposure or file corruption.

## Recommendation

* Audit Samba configurations to identify if the experimental `vfs_ceph_rgw` module is currently enabled in production environments.
* Disable the `vfs_ceph_rgw` module if it is not strictly required for operations until a vendor-supplied patch is applied.
* Monitor Samba access logs for unusual patterns of file access requests involving case-sensitive/insensitive variations for the same file path.
