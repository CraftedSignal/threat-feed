---
title: Multiple Vulnerabilities in NetApp Products
slug: 2026-06-netapp-vulns
description: Multiple vulnerabilities in NetApp products, including CVE-2023-0482, CVE-2023-20863, CVE-2024-22257, CVE-2025-23367, CVE-2025-48976, CVE-2025-53816, and CVE-2025-53817, could lead to remote denial of service, data confidentiality breaches, and data integrity breaches.
date: "2026-06-01T15:30:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:redhat:resteasy:3.15.4:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:resteasy:4.7.7:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:resteasy:5.0.5:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:resteasy:6.2.2:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:linux:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:vsphere:*:*
  - cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:windows:*:*
  - cpe:2.3:a:netapp:oncommand_workflow_automation:-:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:jboss_enterprise_application_platform:*:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:wildfly:*:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:wildfly:28.0.0:beta1:*:*:*:*:*:*
  - cpe:2.3:a:apache:commons_fileupload:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:commons_fileupload:2.0.0:m1:*:*:*:*:*:*
  - cpe:2.3:a:apache:commons_fileupload:2.0.0:m1-rc1:*:*:*:*:*:*
  - cpe:2.3:a:apache:commons_fileupload:2.0.0:m2:*:*:*:*:*:*
  - cpe:2.3:a:apache:commons_fileupload:2.0.0:m2-rc1:*:*:*:*:*:*
  - cpe:2.3:a:apache:commons_fileupload:2.0.0:m3:*:*:*:*:*:*
  - cpe:2.3:a:apache:commons_fileupload:2.0.0:m3-rc1:*:*:*:*:*:*
  - cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - netapp
  - denial-of-service
  - data-breach
  - integrity
vendors:
  - NetApp
  - VMware
  - Brocade
  - Microsoft
products:
  - Active IQ Unified Manager
  - Brocade SAN Navigator (SANnav)
  - ONTAP tools pour VMware vSphere
affected_os:
  - Microsoft Windows
cves:
  - id: CVE-2023-0482
    cvss: 5.5
    epss: 0.0005
  - id: CVE-2025-23367
    cvss: 6.5
    epss: 0.00199
  - id: CVE-2025-48976
    cvss: 7.5
    epss: 0.01278
  - id: CVE-2025-53816
    cvss: 7.5
    epss: 0.00459
  - id: CVE-2025-53817
    cvss: 7.5
    epss: 0.00368
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0671/
  - https://security.netapp.com/advisory/NTAP-20230427-0001
  - https://security.netapp.com/advisory/NTAP-20240419-0005
  - https://security.netapp.com/advisory/NTAP-20240524-0015
  - https://security.netapp.com/advisory/NTAP-20250829-0002
  - https://security.netapp.com/advisory/NTAP-20251107-0004
  - https://security.netapp.com/advisory/NTAP-20251128-0012
  - https://security.netapp.com/advisory/NTAP-20260102-0015
  - https://www.cve.org/CVERecord?id=CVE-2023-0482
  - https://www.cve.org/CVERecord?id=CVE-2023-20863
  - https://www.cve.org/CVERecord?id=CVE-2024-22257
  - https://www.cve.org/CVERecord?id=CVE-2025-23367
  - https://www.cve.org/CVERecord?id=CVE-2025-48976
  - https://www.cve.org/CVERecord?id=CVE-2025-53816
  - https://www.cve.org/CVERecord?id=CVE-2025-53817
rules:
  - title: Detects CVE-2023-0482 exploitation attempts
    description: Detects potential exploitation attempts targeting CVE-2023-0482
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects suspicious access patterns to NetApp management interfaces
    description: Detects anomalous access patterns indicative of potential exploitation attempts to NetApp management interfaces
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

On June 1, 2026, CERT-FR published an advisory regarding multiple vulnerabilities discovered in NetApp products. These vulnerabilities, detailed in NetApp security bulletins NTAP-20230427-0001, NTAP-20240419-0005, NTAP-20240524-0015, NTAP-20250829-0002, NTAP-20251107-0004, NTAP-20251128-0012, and NTAP-20260102-0015, can potentially lead to remote denial of service (DoS), data confidentiality breaches, and data integrity breaches. The affected products include Active IQ Unified Manager for Linux, Microsoft Windows, and VMware vSphere, Brocade SAN Navigator (SANnav), and ONTAP tools for VMware vSphere. Successful exploitation of these vulnerabilities could have significant implications for organizations relying on these NetApp products for data storage and management. Defenders should apply the appropriate patches.

## Attack Chain

1.  Attacker identifies a vulnerable NetApp product exposed to the network, such as Active IQ Unified Manager, Brocade SAN Navigator, or ONTAP tools for VMware vSphere.
2.  The attacker exploits a vulnerability (e.g., CVE-2023-0482, CVE-2023-20863, CVE-2024-22257, CVE-2025-23367, CVE-2025-48976, CVE-2025-53816, CVE-2025-53817) to gain unauthorized access or execute arbitrary code.
3.  If the vulnerability leads to remote code execution, the attacker executes commands to further compromise the system.
4.  The attacker leverages the initial access to escalate privileges within the compromised NetApp system.
5.  Depending on the vulnerability, the attacker might be able to access sensitive data stored within the NetApp environment, leading to a data confidentiality breach.
6.  The attacker could modify or delete data, resulting in a data integrity breach, or disrupt services, causing a denial-of-service condition.
7.  The attacker could use the compromised system as a pivot point to attack other systems on the network.

## Impact

Successful exploitation of these vulnerabilities can lead to several negative outcomes. A remote denial of service (DoS) can disrupt critical business operations. Data confidentiality breaches can expose sensitive information, leading to financial loss and reputational damage. Data integrity breaches can corrupt data, making it unusable or unreliable. The number of victims and sectors targeted are unknown, but the potential impact is significant for organizations using the affected NetApp products.

## Recommendation

*   Apply the patches provided by NetApp for the identified vulnerabilities in Active IQ Unified Manager, Brocade SAN Navigator (SANnav), and ONTAP tools pour VMware vSphere as detailed in the NetApp security bulletins referenced in the documentation section.
*   Deploy the Sigma rule detecting exploitation attempts against CVE-2023-0482 to identify and respond to potential attacks.
*   Monitor network traffic for suspicious activity related to the exploitation of these vulnerabilities.
*   Prioritize patching systems running Active IQ Unified Manager for Linux and Windows, given its central role in managing NetApp storage infrastructure.
*   Regularly review and update security configurations for NetApp products to minimize the attack surface.
