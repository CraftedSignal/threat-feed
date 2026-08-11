---
title: Gunra Ransomware Gang Exploitation of Fortinet Appliances
slug: 2026-08-gunra-ransomware
description: The Gunra ransomware-as-a-service group is leveraging critical Fortinet vulnerabilities (CVE-2024-55591 and CVE-2025-24472) to gain initial access, hijack VDI sessions, and bypass multi-factor authentication in attacks against critical infrastructure.
date: "2026-08-11T21:47:28Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Gunra
cpes:
  - cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*
tags:
  - ransomware
  - fortinet
  - vpn
  - critical-infrastructure
  - authentication-bypass
vendors:
  - Fortinet
products:
  - FortiOS
  - FortiProxy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The FBI observed Gunra actors using two known exploited vulnerabilities in Fortinet products for initial access.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: This includes OS credential dumping and, in one case, compromising a Hiware access control server, stealing the encryption key, and decrypting passwords stored in the database.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: the Gunra actors modified authentication processing files on the corporate VDI authentication portal server to allow successful authentication when a specific, Gunra-designated one time password (OTP) value was entered
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: the FBI observed an attack in which Gunra affiliates deleted backups and archived data stored at both the victim's primary data center and disaster recovery center
    confidence_band: high
cves:
  - id: CVE-2024-55591
    cvss: 9.8
    epss: 0.98259
  - id: CVE-2025-24472
    cvss: 8.1
    epss: 0.03873
references:
  - https://www.darkreading.com/cyberattacks-data-breaches/gunra-ransomware-gang-fortinet-flaws-bypasses-mfa
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch CVE-2024-55591 and CVE-2025-24472 on all FortiOS and FortiProxy appliances.
      owner: IT Operations
      due: 24h
      evidence: Source advisory identifies these as the primary initial access vector.
  mitigation_plan:
    - priority: immediate
      action: Review VDI portal authentication configurations for unauthorized file modifications.
      owner: SOC
      addresses: MFA bypass technique
      evidence: Gunra actors modify authentication processing files on VDI servers.
---

The Gunra ransomware-as-a-service (RaaS) operation has emerged as a significant threat to global critical infrastructure, including healthcare, financial services, and government sectors. First observed in spring 2025, the group utilizes leaked Conti source code to conduct double-extortion attacks. Since early 2026, Gunra has expanded through an affiliate program, attracting less-sophisticated actors by providing user-friendly management panels and customizable ransomware builders. Gunra is notably characterized by its focus on identity and access management (IAM) infrastructure, frequently conducting credential dumping, session hijacking, and the manipulation of authentication files on VDI portals to circumvent multifactor authentication (MFA). Recent reporting by a joint multi-agency coalition identifies the group's use of N-day vulnerabilities in Fortinet appliances for initial access, specifically CVE-2024-55591 and CVE-2025-24472.

## Attack Chain

1. Attackers identify internet-facing Fortinet VPN or firewall appliances vulnerable to CVE-2024-55591 or CVE-2025-24472.
2. The threat actors exploit the authentication bypass vulnerabilities to gain administrative access to the network appliance.
3. Attackers leverage the appliance's traffic control functionality to intercept credentials and session cookies from users accessing the corporate virtual desktop infrastructure (VDI).
4. Stolen session cookies are used to hijack legitimate VDI sessions, effectively bypassing MFA requirements.
5. The actors gain persistence and deeper access by modifying authentication processing files on the VDI gateway to accept attacker-designated OTP values.
6. Attackers conduct lateral movement and credential dumping, including harvesting keys from access control servers and dumping memory on compromised hosts.
7. The group identifies and deletes primary and disaster recovery backups to prevent restoration.
8. Final objective is reached via the deployment of Gunra ransomware to encrypt target files, followed by data exfiltration for double extortion.

## Impact

Gunra has successfully targeted organizations across North and South America, Europe, the Middle East, Africa, and the Asia-Pacific region, with notable concentrations of activity in Brazil and South Korea. Successful compromises result in catastrophic operational disruption, loss of critical data via encryption, and exposure of sensitive information. The group's ability to delete offsite backups and manipulate identity verification mechanisms significantly elevates the recovery time and security risk for affected entities.

## Recommendation

* Patch CVE-2024-55591 and CVE-2025-24472 on all internet-facing Fortinet VPN and firewall appliances immediately.
* Implement offline, immutable backups for primary and disaster recovery data centers to prevent total data loss during a ransomware event.
* Monitor authentication logs and file integrity for critical identity and access management servers, including VDI portals, for unauthorized modifications.
* Enforce strict network segmentation to limit the reach of attackers who achieve initial access via perimeter appliances.
