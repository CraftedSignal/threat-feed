---
title: Vulnerability in Veeam Backup & Replication Allows Privilege Escalation
slug: 2026-07-veeam-br-privesc
description: A privilege escalation vulnerability has been discovered in Veeam Backup & Replication, affecting versions prior to 12.3.0.65, which allows an attacker to elevate their privileges within the system.
date: "2026-07-15T14:36:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - privilege-escalation
  - veeam
vendors:
  - Veeam
products:
  - Backup & Replication
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0878/
  - https://www.veeam.com/kb4879
iocs:
  - type: url
    value: https://www.veeam.com/kb4879
ioc_counts:
  url: 1
---

CERT-FR has issued an advisory regarding a vulnerability identified in Veeam Backup & Replication, a widely used data protection and disaster recovery solution. The vulnerability, detailed in Veeam security bulletin kb4879, allows an attacker to achieve privilege escalation within the affected system. This means that an unauthorized user or a user with lower privileges could potentially gain higher-level access, potentially leading to unauthorized data access, system modification, or disruption of backup operations. The vulnerability affects all Veeam Backup & Replication versions prior to 12.3.0.65. While the advisory does not detail specific exploitation methods or observed in-the-wild attacks, the potential for an attacker to gain elevated access to critical backup infrastructure poses a significant risk to data integrity and availability, making immediate patching crucial for defenders.

## Impact

Successful exploitation of this privilege escalation vulnerability in Veeam Backup & Replication could allow an attacker to gain administrative control over the backup infrastructure. This level of access enables an adversary to tamper with backups, delete critical recovery points, exfiltrate sensitive data stored within backups, or deploy ransomware that impacts an organization's recovery capabilities. Given that Veeam Backup & Replication is often a central component of an organization's business continuity plan, compromise could have a severe impact on an organization's ability to recover from other incidents, potentially leading to significant data loss, operational downtime, and regulatory non-compliance. Specific victim counts or targeted sectors were not disclosed in the advisory.

## Recommendation

* Consult the Veeam security bulletin kb4879 (linked in references) to obtain and apply the necessary patches for Veeam Backup & Replication versions prior to 12.3.0.65 immediately.
