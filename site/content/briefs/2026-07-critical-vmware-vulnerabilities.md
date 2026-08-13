---
title: Critical Vulnerabilities in VMware vCenter and ESX Products
slug: 2026-07-critical-vmware-vulnerabilities
description: Multiple critical vulnerabilities, including CVE-2026-59309 and CVE-2026-59310 with CVSS 9.8, affect VMware vCenter and ESX/ESXi products, enabling unauthorized access without credentials, arbitrary code execution, virtualization escape, information disclosure, and defense evasion, which could lead to full system compromise and data breaches.
date: "2026-07-29T14:55:03Z"
lastmod: "2026-08-13T09:10:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
tags:
  - virtualization
  - critical-vulnerability
  - rce
  - unauthorized-access
  - privilege-escalation
  - defense-evasion
  - esxi
  - vcenter
vendors:
  - VMware
  - Broadcom
products:
  - VMware vCenter
  - VMware ESX
  - VMware ESXi
  - vCenter (8.0, 9.0.x.x, 9.1.x.x)
  - ESX (8.0, 9.0.x.x, 9.1.x.x)
  - Workstation (26H1)
  - Fusion (26H1)
  - Cloud Foundation (5.x, 9.0.x.x, 9.1.x.x)
  - vSphere Foundation (9.0.x.x, 9.1.x.x)
  - vCenter Server
  - VMware Cloud Foundation
  - VMware vSphere Foundation
  - VMware Telco Cloud Platform
  - VMware Telco Cloud Infrastructure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'CVE-2026-59309: Een kwetsbaarheid in VMware vCenter die het mogelijk maakt om zonder juiste inloggegevens toegang te krijgen tot het systeem.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'CVE-2026-59310: Een kwetsbaarheid in de Syslog-server van VMware vCenter waardoor een aanvaller willekeurige code kan uitvoeren en toegang kan krijgen tot bestanden buiten de normale mappen.'
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'CVE-2026-47876: Een kwetsbaarheid in VMware ESXi die een aanvaller met lokale beheerdersrechten op een virtuele machine in staat stelt om code uit te voeren op de onderliggende fysieke server.'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: 'CVE-2026-41709: Een kwetsbaarheid waarbij bepaalde acties niet worden geregistreerd in de logbestanden, waardoor misbruik moeilijk te detecteren is.'
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: 'CVE-2026-41703: Een kwetsbaarheid die kan leiden tot het uitlekken van informatie of instabiliteit binnen virtuele omgevingen.'
    confidence_band: med
cves:
  - id: CVE-2026-59309
    cvss: 9.8
    epss: 0.00744
  - id: CVE-2026-59310
    cvss: 9.8
    epss: 0.0114
  - id: CVE-2026-41703
    cvss: 7.6
    epss: 0.00556
  - id: CVE-2026-41709
    cvss: 2.7
    epss: 0.00382
  - id: CVE-2026-47876
    cvss: 9.3
    epss: 0.00281
references:
  - https://www.ncsc.nl/alerts/kritieke-kwetsbaarheden-in-vmware-vcenter-en-esx-producten-update-onmiddellijk
  - https://thehackernews.com/2026/07/three-critical-vmware-flaws-allow-auth.html
  - https://www.rapid7.com/blog/post/etr-critical-vmware-vcenter-vulnerabilities-allow-authentication-bypass-and-remote-code-execution-cve-2026-59309-cve-2026-59310
  - https://www.securityweek.com/critical-vmware-vcenter-vulnerability-in-attackers-crosshairs/
updates:
  - at: "2026-07-29T15:45:39Z"
    level: L2
    summary: added CVE-2026-41703 +4
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/three-critical-vmware-flaws-allow-auth.html
  - at: "2026-07-30T13:40:27Z"
    level: L2
    summary: poc_available
    sources:
      - rapid7
    source_urls:
      - https://www.rapid7.com/blog/post/etr-critical-vmware-vcenter-vulnerabilities-allow-authentication-bypass-and-remote-code-execution-cve-2026-59309-cve-2026-59310
  - at: "2026-08-13T09:10:01Z"
    level: L2
    summary: added CVE-2026-41709
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/critical-vmware-vcenter-vulnerability-in-attackers-crosshairs/
---

The National Cyber Security Centre (NCSC) has issued an alert regarding multiple critical vulnerabilities affecting VMware vCenter and ESX/ESXi products. Among these are CVE-2026-59309 and CVE-2026-59310, both carrying a CVSS score of 9.8, indicating severe impact with a moderate chance of exploitation and a high potential for damage. These vulnerabilities allow for unauthorized access without proper login credentials, arbitrary code execution via the Syslog server, and a virtualization escape where a local administrator on a virtual machine can execute code on the underlying physical server. Additional flaws include information disclosure (CVE-2026-41703) and a logging bypass (CVE-2026-41709) that hinders detection of malicious actions. Organizations using VMware vCenter and ESX for managing and running virtual machines are strongly advised to install available updates immediately to mitigate risks.

## Attack Chain

1. An unauthenticated attacker exploits CVE-2026-59309 to gain unauthorized access to VMware vCenter without needing proper login credentials.
2. Leveraging CVE-2026-59310, the attacker exploits a vulnerability in the VMware vCenter Syslog server to achieve arbitrary code execution on the vCenter server.
3. Successful exploitation of CVE-2026-59310 also allows the attacker to access and manipulate files outside of the normal directories on the vCenter system.
4. With local administrator rights on a compromised virtual machine, an attacker exploits CVE-2026-47876 to execute code on the underlying physical ESXi server, effectively escaping the virtualized environment.
5. The attacker may exploit CVE-2026-41703 to cause information leakage or instability within the virtualized environments, potentially exposing sensitive data.
6. To evade detection, the attacker may exploit CVE-2026-41709, which causes certain malicious actions to go unrecorded in the log files, making forensic analysis challenging.
7. Upon gaining full control over vCenter or the ESXi host, the attacker can install additional malware, exfiltrate sensitive data, or disrupt business-critical virtualized services.
8. The ultimate objective is often complete compromise of the virtualized infrastructure, leading to data breaches, operational disruption, and significant financial and reputational damage.

## Impact

Failure to address these critical vulnerabilities allows malicious actors to gain unauthorized access to IT systems, view sensitive data, and potentially take control of underlying servers. This could result in severe data breaches, significant disruption of business processes, and a loss of trust among customers and partners. The high CVSS scores and NCSC's urgent advisory underscore the potential for widespread and critical damage to an organization's virtualized infrastructure if these flaws are not patched immediately.

## Recommendation

* Patch CVE-2026-59309, CVE-2026-59310, CVE-2026-47876, CVE-2026-41703, and CVE-2026-41709 by installing VMware-released updates for vCenter and ESX products as soon as possible.
* Restrict access to VMware vCenter and ESXi to only secure management environments; ensure direct internet access is not permitted.
* Consult with your IT service provider if you are unsure whether your organization uses affected VMware products or versions.
