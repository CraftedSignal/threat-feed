---
title: Oracle VirtualBox Unauthenticated RDP Denial-of-Service Vulnerability (CVE-2026-35245)
slug: 2026-04-virtualbox-dos
description: An unauthenticated attacker with network access via RDP can exploit CVE-2026-35245 in Oracle VM VirtualBox version 7.2.6 to cause a denial-of-service (DOS) condition.
date: "2026-04-21T21:16:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - virtualbox
  - rdp
  - dos
  - cve-2026-35245
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-35245
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35245
rules:
  - title: Detect Suspicious RDP Connections
    description: Detects RDP connections from unusual source IPs or to unusual destination ports that may indicate exploitation attempts targeting CVE-2026-35245.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Repeated RDP Connection Errors
    description: Detects repeated RDP connection errors to a host, which can indicate a denial-of-service attempt using malformed RDP requests.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-35245 is a vulnerability affecting Oracle VM VirtualBox version 7.2.6. This vulnerability resides in the Core component of VirtualBox and can be exploited by unauthenticated attackers with network access to the RDP service. Successful exploitation leads to a denial-of-service (DOS) condition, causing the VirtualBox application to hang or crash. The vulnerability's ease of exploitation makes it a significant threat to systems running vulnerable versions of VirtualBox exposed to untrusted networks. This vulnerability allows an attacker to disrupt virtual machine operations, potentially impacting services relying on the virtualized environment.

## Attack Chain

1. The attacker identifies a target system running Oracle VM VirtualBox version 7.2.6 with the RDP service exposed.
2. The attacker establishes a network connection to the target system's RDP port (typically TCP 3389).
3. The attacker sends a specially crafted RDP request to the vulnerable VirtualBox instance, exploiting CVE-2026-35245.
4. The malicious RDP request triggers a flaw within the VirtualBox Core component.
5. The VirtualBox application enters a hung state due to the unhandled exception.
6. Alternatively, the VirtualBox application may crash due to the exploited vulnerability.
7. The virtual machines hosted on the affected VirtualBox instance become unavailable.
8. The attacker successfully causes a denial-of-service (DOS) condition, disrupting VirtualBox operations.

## Impact

Successful exploitation of CVE-2026-35245 results in a denial-of-service condition, where the Oracle VM VirtualBox application hangs or crashes. This impacts the availability of virtual machines running on the affected VirtualBox instance, potentially disrupting critical services and applications. The vulnerability affects VirtualBox version 7.2.6 and poses a risk to organizations utilizing this virtualization platform, especially those with exposed RDP services. The CVSS v3.1 base score is 7.5, reflecting the high availability impact.

## Recommendation

*   Upgrade Oracle VM VirtualBox to a version beyond 7.2.6 to patch CVE-2026-35245.
*   Implement network segmentation and access controls to restrict access to the RDP service, mitigating the risk of external attackers exploiting CVE-2026-35245.
*   Monitor RDP connections for suspicious activity, such as connections from unexpected source IPs, to detect potential exploitation attempts targeting CVE-2026-35245.
*   Deploy the Sigma rule `DetectSuspiciousRDPConnections` to identify unusual RDP activity that may indicate exploitation attempts.
