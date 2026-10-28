---
brief_id: brief-2026-10-28-paragon-driver-lpe
event_id: brief-2026-10-28-paragon-driver-lpe
revision: 1
activity_at: "2026-10-28T22:36:17Z"
title: 'Paragon Software: biontdrv.sys local privilege escalation (CVE-2025-0288)'
slug: 2026-10-paragon-driver-lpe
description: CVE-2025-0288 is a local privilege escalation vulnerability in the biontdrv.sys Windows driver used by multiple Paragon Software products, for which a proof-of-concept exploit is publicly available.
date: "2026-10-28T22:36:17Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified vendor products and CVE-2025-0288 details against provided source.
cpes:
  - cpe:2.3:a:paragon-software:paragon_backup_\&_recovery:*:*:*:*:*:*:*:*
  - cpe:2.3:a:paragon-software:paragon_disk_wiper:*:*:*:*:*:*:*:*
  - cpe:2.3:a:paragon-software:paragon_drive_copy:*:*:*:*:*:*:*:*
  - cpe:2.3:a:paragon-software:paragon_hard_disk_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:paragon-software:paragon_migrate_os_to_ssd:*:*:*:*:*:*:*:*
  - cpe:2.3:a:paragon-software:paragon_partition_manager:*:*:*:*:*:*:*:*
tags:
  - windows
  - privilege-escalation
  - driver
  - vulnerability
vendors:
  - Paragon Software
products:
  - Paragon Backup & Recovery (<= 17.39)
  - Paragon Disk Wiper (<= 16)
  - Paragon Drive Copy (<= 16)
  - Paragon Hard Disk Manager (<= 17.39)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Vulnerable function in biontdrv.sys Windows driver with PoC for CVE-2025-0288.
    confidence_band: high
cves:
  - id: CVE-2025-0288
    cvss: 7.8
    epss: 0.00497
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-MEISAMEB-CVE-2025-0288
  - https://meisameb.github.io/
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-MEISAMEB-CVE-2025-0288&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all endpoints containing biontdrv.sys to identify potentially vulnerable Paragon software installations.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability exists in biontdrv.sys driver within Paragon software.
  hunt_leads:
    - lead: Monitor for unusual process execution or driver-loading behavior associated with Paragon Software binaries, specifically targeting attempts to interact with biontdrv.sys.
      technique_id: T1068
      data_needed:
        - Sysmon Event ID 6 (Driver loaded)
        - Process creation events targeting the identified Paragon product directory
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: PoC code exists targeting the vulnerable function in the driver.
  mitigation_plan:
    - priority: immediate
      action: Patch or update Paragon Backup & Recovery, Disk Wiper, Drive Copy, or Hard Disk Manager to the versions currently recommended by the vendor to remediate the vulnerability in biontdrv.sys.
      owner: IT Operations
      addresses: CVE-2025-0288
      evidence: Vulnerable versions identified in source.
---

A proof-of-concept exploit has been published for CVE-2025-0288, a local privilege escalation vulnerability residing in the 'biontdrv.sys' driver. This driver is associated with several Paragon Software backup and disk management utilities. The vulnerability allows a low-privileged local user to gain high-level system privileges by exploiting an insecure function within the kernel-mode driver.

## Impact

Successful exploitation allows a local user with low privileges to escalate to high-level privileges on the host system. The CVSS 3.1 score of 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) confirms that exploitation provides complete control over confidentiality, integrity, and availability of the affected system.

## Recommendation

- Inventory all systems running Paragon Software products, specifically checking for the presence of the 'biontdrv.sys' driver.
- Prioritize patching for systems where Paragon Software products are installed, as a public PoC is now available.
- Monitor for the execution of the identified PoC or related exploitation tools on workstations where Paragon software is deployed.
- Ensure that Windows driver integrity and security hardening policies are enforced to mitigate potential kernel-level exploitation attempts.
