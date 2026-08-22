---
title: August 2026 Microsoft Security Update Analysis
slug: 2026-08-august-patch-tuesday
description: Microsoft's August 2026 security release addresses 415 vulnerabilities, including a zero-day (CVE-2026-68820) exploited in the wild that enables local privilege escalation in the Windows Ancillary Function Driver for WinSock.
date: "2026-08-12T05:46:15Z"
lastmod: "2026-08-22T07:14:26Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:x64:*
tags:
  - vulnerability-management
  - patch-tuesday
  - windows
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Windows
  - Windows Ancillary Function Driver for WinSock
  - Windows User Profile Service
  - Windows Kernel
  - Windows Container Isolation FS Filter Driver
  - Microsoft QUIC
  - Office
  - Microsoft Office
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: CVE-2026-68820 is an Important elevation of privilege vulnerability affecting the Windows Ancillary Function Driver for WinSock and has a CVSS score of 7.0.
    confidence_band: high
cves:
  - id: CVE-2026-68820
    cvss: 7
    epss: 0.00332
  - id: CVE-2026-62832
    cvss: 7.8
    epss: 0.02365
  - id: CVE-2026-62737
    cvss: 7.8
    epss: 0.00333
  - id: CVE-2026-72971
    cvss: 5.5
    epss: 0.00357
  - id: CVE-2026-62815
    cvss: 9.8
    epss: 0.00916
references:
  - https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-august-2026/
updates:
  - at: "2026-08-22T01:14:19Z"
    level: L1
    summary: new product
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-august-2026/
  - at: "2026-08-22T07:14:26Z"
    level: L1
    summary: new product
    sources:
      - crowdstrike
    source_urls:
      - https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-august-2026/
---

Microsoft's August 2026 Patch Tuesday release addresses 415 unique vulnerabilities across multiple product families, with a focus on Windows OS and associated services. The most significant threat is the actively exploited zero-day, CVE-2026-68820, a use-after-free vulnerability in the Windows Ancillary Function Driver for WinSock that permits local attackers to escalate privileges to SYSTEM. Defenders should prioritize patching this vulnerability due to documented in-the-wild exploitation.

Additionally, the update includes fixes for three publicly disclosed vulnerabilities, including two elevation of privilege flaws (CVE-2026-62832 and CVE-2026-62737) and one tampering vulnerability in the Windows Container Isolation FS Filter Driver (CVE-2026-72971). A critical RCE vulnerability in the Microsoft QUIC protocol (CVE-2026-62815) also requires immediate attention, as it allows unauthenticated attackers to execute code via crafted network packets with a high CVSS score of 9.8.

## Impact

Successful exploitation of the identified vulnerabilities, particularly CVE-2026-68820 and CVE-2026-62815, could lead to complete system compromise, unauthorized data access, and privilege escalation to SYSTEM. The widespread nature of the affected components, including Windows system services and the QUIC transport protocol, poses a significant risk to enterprise environments. Patching is critical to prevent attackers from leveraging these flaws for persistent access or lateral movement within the network.

## Recommendation

* Prioritize the deployment of August 2026 security updates across all Windows assets to remediate the actively exploited zero-day CVE-2026-68820 and the critical RCE CVE-2026-62815.
* Apply security patches for CVE-2026-62832 and CVE-2026-62737 on systems where local attack vectors are a primary concern, such as multi-user workstations and servers.
* Audit container environments for the presence of the Windows Container Isolation FS Filter Driver to assess potential exposure to CVE-2026-72971.
* Deploy monitoring for anomalous privilege escalation attempts on high-value hosts to identify potential exploitation of elevation of privilege vulnerabilities like CVE-2026-68820.
