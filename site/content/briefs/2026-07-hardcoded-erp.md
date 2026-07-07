---
title: 'CVE-2026-14807: PROG MIS ERP App Hard-coded Credentials Vulnerability'
slug: 2026-07-hardcoded-erp
description: An unauthenticated remote attacker can exploit a Use of Hard-coded Credentials vulnerability (CWE-798) in the ERP App developed by PROG MIS, allowing the attacker to log in to view application code and obtain database account and password information, leading to high impact on confidentiality, integrity, and availability.
date: "2026-07-06T08:34:41Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - hard-coded-credentials
  - erp
  - web-application
  - vulnerability
vendors:
  - PROG MIS
products:
  - ERP App
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: ERP App developed by PROG MIS has a Use of Hard-coded Credentials vulnerability, allowing unauthenticated remote attackers to log in
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: ERP App developed by PROG MIS has a Use of Hard-coded Credentials vulnerability
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: allowing unauthenticated remote attackers to log in to view application code and obtain the database account and password.
    confidence_band: high
cves:
  - id: CVE-2026-14807
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14807
  - https://www.twcert.org.tw/en/cp-139-11024-c5c1a-2.html
  - https://www.twcert.org.tw/tw/cp-132-11023-3abe8-1.html
---

A critical vulnerability, tracked as CVE-2026-14807, has been identified in the ERP App developed by PROG MIS. This flaw is categorized as a Use of Hard-coded Credentials (CWE-798), enabling unauthenticated remote attackers to bypass the application's authentication mechanisms. Exploitation of this vulnerability grants attackers unauthorized login access, allowing them to view the application's source code. From the exposed code, attackers can extract sensitive information, specifically the database account and password. This provides a direct path to the underlying database, leading to potential compromise of all data managed by the ERP system. The vulnerability carries a CVSS v3.1 base score of 9.8, underscoring its severe impact on confidentiality, integrity, and availability. All versions of the PROG MIS ERP App are affected.

## Attack Chain

1.  An unauthenticated remote attacker identifies the PROG MIS ERP App as vulnerable to CVE-2026-14807.
2.  The attacker leverages the inherent hard-coded credentials (CWE-798) to gain unauthorized authenticated access to the ERP App without needing valid user credentials.
3.  Upon successful login, the attacker navigates through the application interface to access functionalities that allow viewing or downloading of application code files.
4.  The attacker extracts sensitive hard-coded database connection strings, including the database account username and password, directly from the exposed application code.
5.  Using the newly acquired database credentials, the attacker establishes a direct, unauthorized connection to the ERP system's backend database.
6.  With direct database access, the attacker can then perform various malicious activities, such as exfiltrating sensitive company data, modifying critical business records, or deploying further persistence mechanisms.

## Impact

The successful exploitation of CVE-2026-14807 has a severe impact on affected organizations utilizing the PROG MIS ERP App. Attackers gain complete access to the application's internal code, directly compromising intellectual property and potentially revealing further vulnerabilities. More critically, the database account and password can be obtained, leading to full compromise of the ERP system's underlying database. This allows for unauthorized viewing, modification, or deletion of sensitive financial, customer, and operational data, causing significant data breaches, operational disruption, and reputational damage. Given that ERP systems manage core business processes, the compromise could halt operations and incur substantial recovery costs.

## Recommendation

*   Prioritize patching or applying vendor-provided security updates for the PROG MIS ERP App to mitigate CVE-2026-14807 immediately.
*   Review all application code for the PROG MIS ERP App to identify and remediate any instances of hard-coded credentials (CWE-798), replacing them with secure credential management practices (e.g., environment variables, secret management services).
*   Implement network segmentation to restrict direct database access from the ERP application servers to only necessary ports and services, limiting the blast radius if the application layer is compromised.
*   Conduct a thorough post-incident forensic analysis if exploitation is suspected to identify potential lateral movement or data exfiltration.
