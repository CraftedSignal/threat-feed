---
brief_id: brief-2026-11-09-pardus-boot-repair-traversal
event_id: brief-2026-11-09-pardus-boot-repair-traversal
revision: 1
activity_at: "2026-11-09T10:25:22Z"
title: 'Pardus Boot Repair: Path traversal in pardus-mount-rootfs (CVE-2026-92080)'
slug: 2026-11-pardus-boot-repair-traversal
description: A path traversal vulnerability in the pardus-mount-rootfs helper of pardus-boot-repair allows a malicious /etc/fstab to execute a privileged mount outside of the intended repair root directory.
date: "2026-11-09T10:25:22Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:tubitak:pardus-boot-repair:1.0.8:*:*:*:*:*:*:*
tags:
  - path-traversal
  - linux
  - filesystem-manipulation
vendors:
  - TÜBİTAK BİLGEM Software Technologies Research Institute
products:
  - pardus-boot-repair (1.0.8 through < 1.1.0)
affected_os:
  - Pardus GNU/Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Path traversal in pardus-boot-repair allows privileged mount outside repair root.
    confidence_band: high
cves:
  - id: CVE-2026-92080
    cvss: 4.3
    epss: 0.00277
    kev_status: "false"
references:
  - https://vulners.com/cve/CVE-2026-92080
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-1477
  - https://sploitus.com/exploit?id=03C0A20C-F5ED-5977-8469-BC02FE6D4889
  - https://sploitus.com/exploit?id=03C0A20C-F5ED-5977-8469-BC02FE6D4889&utm_source=rss&utm_medium=rss
iocs:
  - type: hash_sha256
    value: fe3b08d62185a503eddcd3e9abb92b10420a60c01a6b21967833021989662896
ioc_counts:
  hash_sha256: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch pardus-boot-repair to version 1.1.0 or later.
      owner: IT Operations
      due: 48h
      evidence: CNA recommendation for CVE-2026-92080 remediation.
  hunt_leads:
    - lead: Identify systems with vulnerable pardus-mount-rootfs hash and review execution logs for unusual mountpoint parameters.
      technique_id: T1068
      data_needed:
        - Process creation logs including command line arguments for /usr/bin/pardus-mount-rootfs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Research report demonstrates successful mount escape using production helper and crafted fstab.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 1.1.0
      owner: IT Operations
      addresses: CVE-2026-92080
      evidence: Official CVE/CNA recommendation.
---

CVE-2026-92080 is a path traversal vulnerability in the `pardus-mount-rootfs` utility, a component of `pardus-boot-repair`. The vulnerability arises because the utility reads mountpoint paths directly from a target filesystem's `/etc/fstab` and concatenates them without adequate validation. An attacker who can control the `fstab` content of a filesystem processed by this tool can cause the application to perform a mount operation outside of its intended `DESTDIR`, potentially leading to unauthorized filesystem access with elevated privileges.

## Impact
Successful exploitation results in a privileged mount escape, allowing the mounting of filesystems at arbitrary paths on the host. This impacts system integrity by providing an attacker with a mechanism to manipulate or expose file paths on the host system. The specific consequences of such an escape depend on the host environment and the filesystem contents chosen by the attacker.

## Recommendation
- Upgrade `pardus-boot-repair` to version 1.1.0 or later as advised by the vendor.
- Implement monitoring for the usage of the `/usr/bin/pardus-mount-rootfs` utility, particularly when invoked with untrusted or externally sourced filesystem images.
- Audit logs for instances where mount operations result in paths outside of expected repair directories.
