---
title: Multiple Critical Vulnerabilities in Hitachi Energy FACTS Control Platform
slug: 2026-09-hitachi-fcp-vulns
description: Hitachi Energy FACTS Control Platform (FCP) units equipped with the GWS component are affected by multiple critical vulnerabilities, including path traversal and authentication bypass, potentially leading to unauthorized system access or modification.
date: "2026-09-17T17:11:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.4:fixpack_1:*:*:*:*:*:*
  - cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.4:fixpack_2_hf1:*:*:*:*:*:*
  - cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.4:fixpack_2_hf2:*:*:*:*:*:*
  - cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.4:fixpack_2_hf3:*:*:*:*:*:*
  - cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.4:fixpack_2_hf4:*:*:*:*:*:*
  - cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.4:fixpack_2_hf5:*:*:*:*:*:*
  - cpe:2.3:a:hitachienergy:microscada_x_sys600:*:*:*:*:*:*:*:*
  - cpe:2.3:a:hitachienergy:microscada_x_sys600:10.5:*:*:*:*:*:*:*
tags:
  - ics
  - energy
  - ot
  - vulnerability
vendors:
  - Hitachi Energy
products:
  - FACTS Control Platform (FCP) (3.4.0, 3.7.0, 3.8.0, 3.10.0, 3.12.0, 3.14.0, 3.15.0, 4.0.0, 4.0.1, 4.1.0, 4.1.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The FACTS Control system with GWS allows an authenticated user input to control or influence paths or file names that are used in filesystem operations.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The FACTS Control system with GWS product exposes a service that is intended for local only to all network interfaces without any authentication.
    confidence_band: high
cves:
  - id: CVE-2024-3980
    cvss: 9.9
    epss: 0.00611
  - id: CVE-2024-4872
    cvss: 9.9
    epss: 0.00496
  - id: CVE-2024-3982
    cvss: 8.2
    epss: 0.00217
  - id: CVE-2024-7940
    cvss: 8.3
    epss: 0.00579
  - id: CVE-2024-7941
    cvss: 4.3
    epss: 0.00335
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-03
  - https://publisher.hitachienergy.com/preview?DocumentID=8DBD000229&LanguageCode=en&DocumentPartId=&Action=launch
  - https://www.cve.org/CVERecord?id=CVE-2024-4872
  - https://www.cve.org/CVERecord?id=CVE-2024-3980
  - https://www.cve.org/CVERecord?id=CVE-2024-3982
  - https://www.cve.org/CVERecord?id=CVE-2024-7940
  - https://www.cve.org/CVERecord?id=CVE-2024-7941
action_plan:
  priority: immediate_escalation
  owners:
    - OT Security
    - Network Security
  immediate_actions:
    - action: Inventory all FCP deployments to determine if GWS component is present.
      owner: OT Security
      due: 24h
      evidence: Product deployments without GWS component are not affected.
  mitigation_plan:
    - priority: immediate
      action: Review Hitachi Energy advisory 8DBD000229 for patch deployment.
      owner: IT Operations
      addresses: CVE-2024-4872, CVE-2024-3980, CVE-2024-3982, CVE-2024-7940, CVE-2024-7941
      evidence: Please refer to the Recommended Immediate Actions for information about the mitigation/remediation.
---

Hitachi Energy has disclosed a series of critical vulnerabilities affecting the FACTS Control Platform (FCP) specifically when the GWS (Gateway Service) component is present. The vulnerabilities impact systems deployed since 2020, including SVC Light (STATCOM), Fixed Series Capacitor, Thyristor Controlled Series Capacitor, Static Var Compensator, Static Watt Compensator, and Hybrid Synchronous Condensers. The vulnerabilities range from path traversal (CVE-2024-3980) and improper query neutralization (CVE-2024-4872) to authentication bypass via capture-replay (CVE-2024-3982) and missing authentication for critical service functions (CVE-2024-7940). 

These flaws pose a significant risk to the confidentiality, integrity, and availability of power grid control assets. Because the FCP is integrated into critical energy infrastructure, these vulnerabilities are highly sensitive for defenders operating in OT environments. Successful exploitation allows attackers to manipulate sensitive files, inject code, or interact with unauthenticated services, potentially leading to full system compromise or operational disruption.

## Impact

The affected platforms are utilized in critical energy infrastructure worldwide. Successful exploitation could allow a remote or local attacker to modify control logic, access sensitive system configurations, or bypass authentication mechanisms. Given the nature of FACTS systems in stabilizing electrical grids, the potential impact includes severe operational instability, loss of control over grid stabilization hardware, and the compromise of sensitive power transmission control data.

## Recommendation

Prioritize the identification of all FACTS Control Platform (FCP) assets running the GWS component within the OT environment.

- Audit network ingress to identify services exposed by the GWS component that should be restricted to local or trusted internal segment access only, specifically addressing CVE-2024-7940.
- Review internal configuration and access logs for unauthorized file system operations or attempts to access restricted paths, which may indicate exploitation attempts for CVE-2024-3980.
- Enforce strict role-based access control and disable unnecessary session logging features on FCP systems to mitigate the prerequisite requirements for CVE-2024-3982.
- Coordinate with Hitachi Energy representatives to obtain the specific security advisory 8DBD000229 for remediation instructions and patch availability for affected FCP versions.
