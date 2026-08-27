---
title: Insufficient Work Factor in Rockwell Automation OTTO Fleet Manager
slug: 2026-08-rockwell-otto-hash
description: Rockwell Automation OTTO Fleet Manager versions V2.36.2 and earlier use an insufficient work factor for bcrypt password hashing, enabling attackers with access to system backups to perform efficient offline brute-force attacks.
date: "2026-08-27T16:05:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Rockwell Automation
products:
  - OTTO Fleet Manager
cves:
  - id: CVE-2026-75112
    epss: 0.00113
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-239-03
  - https://www.cve.org/CVERecord?id=CVE-2026-75112
  - https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.SD1791.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit environment for OTTO Fleet Manager version 2.36.2 or earlier
      owner: IT Operations
      due: 72h
      evidence: Affected products list in CVE-2026-75112
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 2.36.3
      owner: IT Operations
      addresses: CVE-2026-75112
      evidence: Remediation section of ICSA-26-239-03
---

Rockwell Automation has disclosed a security vulnerability, identified as CVE-2026-75112, affecting the OTTO Fleet Manager software in versions V2.36.2 and earlier. The issue lies in the implementation of the bcrypt password hashing algorithm, which utilizes an insufficient work factor. This deficiency significantly lowers the computational effort required for an attacker to conduct offline brute-force attacks against stored password hashes. The threat is most relevant in scenarios where an attacker successfully obtains a copy of an unencrypted system backup. Because this vulnerability facilitates the compromise of credentials post-exfiltration, it represents a risk to the integrity of account access within industrial environments managed by this software.

## Impact

Successful exploitation could result in the compromise of user credentials stored within the OTTO Fleet Manager system. By reducing the computational cost of cracking hashes, attackers can more rapidly gain unauthorized access to the application, potentially impacting critical manufacturing and transportation systems where these units are deployed worldwide. The risk is limited to scenarios involving local or network access to unencrypted backup files.

## Recommendation

- Upgrade all instances of OTTO Fleet Manager to version 2.36.3 or later to remediate the bcrypt work factor deficiency.
- Enable encrypted system backups in OTTO Fleet Manager configuration as per the guidance in Rockwell Automation security advisory SD1791.
- Restrict access to system backup files to highly privileged service accounts and implement robust monitoring to detect unauthorized file access or exfiltration.
- Implement network segmentation to isolate OTTO Fleet Manager instances from broader business networks, limiting the potential for lateral movement and access to sensitive backup data.
