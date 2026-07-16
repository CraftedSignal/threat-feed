---
title: Privilege Escalation Vulnerability in SALTO ProAccess Space
slug: 2026-07-privilege-escalation-salto-proaccess
description: An authenticated attacker can exploit CVE-2026-11889, a privilege escalation vulnerability in SALTO ProAccess Space versions prior to 6.13, to bypass authorization controls and access spaces outside their assigned partition within the same installation, provided the partitioning feature is enabled.
date: "2026-07-16T16:11:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - ICS
  - authorization-bypass
vendors:
  - SALTO
products:
  - SALTO ProAccess Space <6.13
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Successful exploitation of this vulnerability allows an authenticated attacker to escalate privileges and access spaces outside their assigned partition
    confidence_band: high
cves:
  - id: CVE-2026-11189
    cvss: 6.5
    epss: 0.00172
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-197-07
  - https://www.cve.org/CVERecord?id=CVE-2026-11889
---

CISA has released an advisory concerning CVE-2026-11889, a privilege escalation vulnerability affecting SALTO ProAccess Space versions prior to 6.13. This flaw, categorized as an Authorization Bypass Through User-Controlled Key (CWE-639), allows an authenticated attacker to gain unauthorized access to spaces beyond their assigned logical partition within the same SALTO ProAccess Space installation. Exploitation requires valid operator credentials and the partitioning feature to be actively enabled within the system. SALTO ProAccess Space is widely used in commercial facilities and critical manufacturing sectors globally for access control and security management. While no public exploitation has been reported to CISA, the vulnerability poses a risk of internal data or access control system compromise for organizations utilizing the affected software with partitioning enabled, impacting the confidentiality and integrity of their access management.

## Attack Chain

1. An attacker obtains valid operator credentials for a SALTO ProAccess Space instance.
2. The attacker authenticates to the SALTO ProAccess Space application using the compromised credentials.
3. The authenticated attacker exploits CVE-2026-11889 by manipulating an authorization check via a user-controlled key, bypassing the assigned partition controls.
4. The system grants the attacker unauthorized access to spaces or data outside their legitimate assigned logical partition.
5. The attacker can then view or manipulate access controls and sensitive information associated with the unauthorized partitions.

## Impact

Successful exploitation of CVE-2026-11889 allows an authenticated attacker to escalate their privileges within the SALTO ProAccess Space application, gaining unauthorized access to spaces and data outside their assigned partition. This could lead to a breach of sensitive access control information, unauthorized modification of access rights for physical spaces, and potential disruption of security operations within affected organizations. The vulnerability specifically impacts critical infrastructure sectors such as Commercial Facilities and Critical Manufacturing, which rely on SALTO ProAccess Space for secure access management. While no known public exploitation has been reported, the compromise of logical partition separation could have significant consequences for security and compliance.

## Recommendation

* Upgrade all SALTO ProAccess Space installations to version 6.13 or later to remediate CVE-2026-11189.
* Operate SALTO ProAccess Space on a protected internal network and avoid direct exposure to the internet, as recommended by SALTO.
* Restrict operator-level accounts within SALTO ProAccess Space to the minimum required permissions, adhering to least-privilege principles.
* If strong tenant separation is not critical, consider disabling the partitioning feature in SALTO ProAccess Space; alternatively, run separate isolated instances instead of relying solely on logical partitioning.
