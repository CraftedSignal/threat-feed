---
title: ClamAV Vulnerabilities Lead to Denial of Service in Cisco Secure Endpoint Products
slug: 2026-07-clamav-cisco-dos
description: Multiple vulnerabilities (CVE-2026-20213, CVE-2026-20214, CVE-2026-20215, CVE-2026-20216, CVE-2026-20217, CVE-2026-20243, CVE-2026-20244) in ClamAV, as integrated into Cisco Secure Endpoint Connector, allow a remote attacker to cause a denial of service (DoS) condition by interrupting scanning operations, with a High severity impact on Windows platforms and Medium on Linux/Mac.
date: "2026-07-01T16:03:29Z"
lastmod: "2026-07-11T07:33:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:cisco:secure_endpoint:*:*:*:*:*:macos:*:*
  - cpe:2.3:a:cisco:secure_endpoint:*:*:*:*:*:linux:*:*
  - cpe:2.3:a:cisco:secure_endpoint:*:*:*:*:*:windows:*:*
  - cpe:2.3:a:clamav:clamav:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - dos
  - clamav
  - cisco
  - security-software
vendors:
  - Cisco
  - ClamAV
products:
  - Cisco Secure Endpoint Connector
  - ClamAV < 1.5.3
  - ClamAV < 1.4.5
  - ClamAV
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Multiple vulnerabilities in ClamAV could allow a remote attacker to cause a denial of service (DoS) condition, interrupting scanning operations.
    confidence_band: high
cves:
  - id: CVE-2026-20213
    cvss: 7.5
    epss: 0.00463
  - id: CVE-2026-20244
    cvss: 7.5
    epss: 0.00389
  - id: CVE-2026-20214
    cvss: 7.5
    epss: 0.00463
  - id: CVE-2026-20215
    cvss: 7.5
    epss: 0.00389
  - id: CVE-2026-20216
    cvss: 7.5
    epss: 0.00389
  - id: CVE-2026-20217
    cvss: 7.5
    epss: 0.00389
  - id: CVE-2026-20243
    cvss: 7.5
    epss: 0.00389
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-88cFYyxR?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=ClamAV%20Vulnerabilities%20Affecting%20Cisco%20Products:%20July%202026%26vs_k=1
  - https://blog.clamav.net/2026/07/clamav-153-and-145-security-patch.html
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20217
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20244
updates:
  - at: "2026-07-11T07:32:55Z"
    level: L2
    summary: added CVE-2026-20213 +4
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20217
  - at: "2026-07-11T07:33:03Z"
    level: L2
    summary: added CVE-2026-20217 +1
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20244
---

Cisco has disclosed multiple vulnerabilities within the ClamAV antivirus engine, specifically affecting Cisco Secure Endpoint Connector products. These vulnerabilities, identified collectively with several CVEs including CVE-2026-20213 through CVE-2026-20244, could allow a remote attacker to trigger a denial of service (DoS) condition. This DoS state would interrupt essential ClamAV scanning operations on affected endpoints. The severity rating is High for Windows-based platforms because the ClamAV scanning process operates in a privileged security context on those systems, whereas Linux and Mac platforms face a Medium impact due to lower-privileged execution. Cisco released software updates on July 1, 2026, to address these issues, emphasizing that no workarounds are available, necessitating immediate patching.

## Attack Chain

1. A remote attacker crafts a specially malformed file designed to exploit one of the identified ClamAV vulnerabilities (e.g., CVE-2026-20213).
2. The attacker delivers this malicious file to a target system running an unpatched version of Cisco Secure Endpoint Connector.
3. Cisco Secure Endpoint Connector initiates a file scan, processing the malicious file using its integrated ClamAV engine.
4. During the scanning process, the malformed file interacts with the vulnerable component of ClamAV, triggering the denial of service condition.
5. The ClamAV scanning process crashes or becomes unresponsive, leading to an interruption of security scanning operations on the endpoint.
6. On Windows platforms, where ClamAV runs with elevated privileges, the impact of this DoS is rated High, potentially affecting system stability or overall security posture.
7. On Linux and Mac platforms, where ClamAV operates with lower privileges, the DoS impact is rated Medium, likely confined to the scanning process itself.
8. The endpoint remains vulnerable due to the interruption of critical antivirus scanning capabilities.

## Impact

The primary impact of these vulnerabilities is a denial of service (DoS) condition within the ClamAV scanning process integrated into Cisco Secure Endpoint Connector. This interruption means that affected systems would temporarily or persistently lose their ability to scan for and detect malicious content, leaving them exposed to other threats. For Windows-based platforms, where ClamAV runs in a privileged security context, the impact is severe (High Security Impact Rating), potentially leading to system instability or a significant degradation of security defenses. On Linux and Mac platforms, the impact is considered Medium due to ClamAV running in a lower-privileged context, which might limit the scope of the DoS to the scanning application itself rather than the entire operating system. The lack of available workarounds means that organizations must apply software updates to mitigate the risk of compromised security posture.

## Recommendation

*   Immediately apply the security updates provided by Cisco to all affected Cisco Secure Endpoint Connector installations, as no workarounds are available to address CVE-2026-20213, CVE-2026-20214, CVE-2026-20215, CVE-2026-20216, CVE-2026-20217, CVE-2026-20243, and CVE-2026-20244.
*   Prioritize patching Cisco Secure Endpoint Connector on Windows platforms due to the higher Security Impact Rating.
*   Refer to the Cisco Security Advisory (https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-88cFYyxR) for specific version information and patch availability.
