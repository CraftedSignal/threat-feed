---
title: 'CVE-2026-8377: Missing Authorization in Armiya GKS Allows Data Collection'
slug: 2026-07-armiya-gks-auth-bypass
description: A critical Missing Authorization vulnerability (CVE-2026-8377) in Armiya Information Technologies Ltd. Co.'s Access Control System (GKS) before Version 2 allows an unauthenticated or unauthorized attacker to collect sensitive data from common resource locations, leading to unauthorized information disclosure.
date: "2026-07-07T08:24:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - access-control-system
  - missing-authorization
  - data-collection
  - critical-infrastructure
vendors:
  - Armiya Information Technologies Ltd. Co.
products:
  - Access Control System (GKS) < Version 2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Missing Authorization vulnerability in Armiya Information Technologies Ltd. Co. Access Control System (GKS) allows Collect Data from Common Resource Locations.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Missing Authorization vulnerability in Armiya Information Technologies Ltd. Co. Access Control System (GKS) allows Collect Data from Common Resource Locations.
    confidence_band: high
cves:
  - id: CVE-2026-8377
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8377
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0502
---

CVE-2026-8377 details a critical Missing Authorization vulnerability within Armiya Information Technologies Ltd. Co.'s Access Control System (GKS), affecting all versions prior to Version 2. Published on July 7, 2026, this flaw (CWE-862) allows an unauthenticated or unauthorized attacker to collect sensitive data from common resource locations managed by the GKS. This directly impacts data confidentiality, as unauthorized individuals can bypass access controls to retrieve information without proper authentication or authorization checks. The vulnerability is assigned a CVSS v3.1 score of 8.2 (High), indicating its severity and the ease with which it can be exploited (AV:N/AC:L/PR:N/UI:N). Defenders must prioritize patching to prevent unauthorized data access and maintain the integrity of their access control system's security posture.

## Impact

The successful exploitation of CVE-2026-8377 can lead to significant unauthorized data disclosure. Attackers can bypass intended access controls within the Armiya Information Technologies Ltd. Co. Access Control System (GKS) to collect data from "common resource locations." While the specific type or volume of data is not detailed in the advisory, access control systems often manage highly sensitive information, including user credentials, access logs, and potentially critical infrastructure configurations. Organizations utilizing vulnerable versions of GKS face a direct risk to data confidentiality, potentially exposing proprietary information, user privacy data, or system configurations to malicious actors. This can lead to compliance violations, reputational damage, and further targeted attacks.

## Recommendation

*   Immediately apply patches provided by Armiya Information Technologies Ltd. Co. to update Access Control System (GKS) to Version 2 or later, addressing CVE-2026-8377.
*   Review logs for unusual access patterns or data collection activities originating from unauthorized sources, especially targeting resources managed by GKS, as indicated by CVE-2026-8377.
