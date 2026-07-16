---
title: Multiple Vulnerabilities in AutomationDirect Productivity Suite Could Lead to Privilege Escalation and DoS
slug: 2026-07-automationdirect-productivity-suite-vulns
description: Multiple vulnerabilities, including out-of-bounds write, out-of-bounds read, and divide-by-zero, exist in AutomationDirect Productivity Suite versions up to and including v4.6.2.2, allowing an attacker with local or physical access to exploit these flaws via crafted IOCTL requests, potentially leading to kernel memory corruption, privilege escalation, information disclosure, application instability, or a denial-of-service condition.
date: "2026-07-16T16:15:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ICS
  - SCADA
  - industrial-control-systems
  - out-of-bounds-write
  - out-of-bounds-read
  - privilege-escalation
  - denial-of-service
  - vulnerability
vendors:
  - AutomationDirect
products:
  - Productivity Suite (<=v4.6.2.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An out-of-bounds write vulnerability in the Productivity Suite allows a local attacker to trigger kernel memory corruption via a crafted IOCTL request, potentially resulting in privilege escalation or system instability.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Successful exploitation of these vulnerabilities could allow an attacker with local or physical access to cause memory corruption, unintended information disclosure, application instability, or a denial-of-service condition in the affected product.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-197-04
  - https://www.cve.org/CVERecord?id=CVE-2026-60063
  - https://www.cve.org/CVERecord?id=CVE-2026-61389
  - https://www.cve.org/CVERecord?id=CVE-2026-60140
  - https://www.cve.org/CVERecord?id=CVE-2026-57896
  - https://www.cve.org/CVERecord?id=CVE-2026-60073
  - https://www.cve.org/CVERecord?id=CVE-2026-61378
---

CISA has released an advisory detailing multiple vulnerabilities, including CVE-2026-60063, CVE-2026-61389, CVE-2026-60140, CVE-2026-57896, CVE-2026-60073, and CVE-2026-61378, affecting AutomationDirect Productivity Suite versions up to and including v4.6.2.2. These vulnerabilities can be exploited by an attacker who has obtained local or physical access to an engineering workstation running the software. By sending specially crafted IOCTL requests, the attacker can trigger kernel memory corruption, out-of-bounds reads, or divide-by-zero errors. Successful exploitation could result in privilege escalation, unintended information disclosure, application instability, or a complete denial-of-service for the affected system. This threat is particularly significant for organizations in the critical manufacturing sector, where such software is widely deployed for industrial control systems.

## Attack Chain

1. Attacker gains local or physical access to an engineering workstation with AutomationDirect Productivity Suite installed.
2. The attacker sends specially crafted Input/Output Control (IOCTL) requests to the vulnerable Productivity Suite component.
3. The crafted IOCTL requests trigger critical memory issues such as out-of-bounds write (CWE-787), out-of-bounds read (CWE-125), or divide-by-zero vulnerabilities within the kernel space.
4. Successful exploitation of out-of-bounds write vulnerabilities (e.g., CVE-2026-60063, CVE-2026-61389) leads to kernel memory corruption.
5. Kernel memory corruption can result in privilege escalation, allowing the attacker to execute arbitrary code with elevated permissions.
6. Out-of-bounds read vulnerabilities (e.g., CVE-2026-60140) cause sensitive information from kernel memory to be disclosed to the attacker.
7. Exploitation of any of these vulnerabilities can lead to application instability or crashes.
8. The instability or crash culminates in a denial-of-service condition, rendering the engineering workstation or the Productivity Suite software unusable.

## Impact

The successful exploitation of these vulnerabilities can have severe consequences, particularly within critical manufacturing environments. An attacker could gain elevated system privileges on an engineering workstation, leading to unauthorized access and control over industrial processes managed by the Productivity Suite. Information disclosure could expose sensitive operational data or proprietary designs. More broadly, application instability and denial-of-service conditions directly impact operational continuity, potentially causing significant downtime, production losses, and safety hazards in industrial control systems worldwide. While no specific victim counts or named campaigns are provided, the widespread deployment in critical infrastructure signifies a substantial risk.

## Recommendation

* Immediately patch AutomationDirect Productivity Suite to v4.7.0.47 or above to remediate CVE-2026-60063, CVE-2026-61389, CVE-2026-60140, CVE-2026-57896, CVE-2026-60073, and CVE-2026-61378.
* Disconnect engineering workstations from external networks (internet, corporate LAN) to reduce exposure, as recommended for CVE-2026-60063.
* Restrict both physical and logical access to engineering workstations to authorized personnel only, as recommended for CVE-2026-61389.
* Configure application whitelisting on engineering workstations to allow only trusted, pre-approved applications to run and block unauthorized software, as recommended for CVE-2026-60140.
* Enable and regularly review system logs on engineering workstations to detect suspicious or unauthorized activity.
