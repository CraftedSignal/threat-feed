---
title: Critical Vulnerability in HPE Unified OSS Console (UOC)
slug: 2026-05-hpe-unified-oss-console-vuln
description: HPE published a security advisory (AV26-477) addressing a critical vulnerability in HPE Unified OSS Console (UOC) version 3.1.20 and prior, potentially leading to unauthorized access and control of network operations.
date: "2026-05-19T16:22:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - hpe
  - oss
  - network-management
vendors:
  - HPE
products:
  - HPE Unified OSS Console (UOC) – version 3.1.20
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://cyber.gc.ca/en/alerts-advisories/hpe-security-advisory-av26-477
  - https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05056en_us&docLocale=en_US
  - https://support.hpe.com/connect/s/securitybulletinlibrary?language=en_US
rules:
  - title: Detect Suspicious Process Creation by HPE UOC
    description: Detects suspicious process creation events originating from the HPE Unified OSS Console (UOC) process, potentially indicating exploitation or unauthorized activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

On May 18, 2026, HPE released security advisory AV26-477 to address a critical vulnerability affecting HPE Unified OSS Console (UOC) version 3.1.20 and earlier. This vulnerability, detailed in HPESBNW05056 rev.1, could allow an attacker to gain unauthorized access to the UOC and potentially compromise network operations. The Unified OSS Console is a centralized management platform used by network operators to monitor and control their infrastructure. Successful exploitation could have significant impact on service availability, data integrity, and overall network security posture. This advisory is a high priority for organizations utilizing the affected HPE UOC versions, emphasizing the need for immediate review and application of the recommended updates.

## Attack Chain

Given the advisory provides no specific exploitation details, the following attack chain is a potential scenario based on common vulnerabilities in similar management consoles:

1.  **Initial Access:** Attacker identifies an accessible HPE Unified OSS Console (UOC) instance running version 3.1.20 or prior.
2.  **Vulnerability Exploitation:** The attacker leverages a vulnerability (e.g., authentication bypass, remote code execution) within the UOC's web interface. This step is hypothetical since the specific vulnerability details aren't disclosed in the advisory.
3.  **Privilege Escalation:** The attacker exploits a local privilege escalation vulnerability within the UOC server operating system to gain root or SYSTEM privileges.
4.  **Credential Access:** The attacker accesses stored credentials within the UOC database or configuration files, potentially including credentials for managed network devices.
5.  **Lateral Movement:** Using the acquired credentials, the attacker moves laterally within the network, accessing and compromising other systems managed by the UOC.
6.  **Data Exfiltration:** The attacker exfiltrates sensitive data from the compromised systems, including network configurations, customer data, or internal documents.
7.  **System Disruption:** The attacker disrupts network services by modifying configurations, disabling devices, or launching denial-of-service attacks.

## Impact

Successful exploitation of the vulnerability in HPE Unified OSS Console (UOC) could allow attackers to gain complete control over network operations. This could result in significant service disruptions, data breaches, and reputational damage. Given the UOC's role in managing critical network infrastructure, the impact could extend to a large number of customers and services. The advisory highlights the urgency of applying the necessary updates to mitigate these risks.

## Recommendation

*   Immediately review the HPE security advisory HPESBNW05056 rev.1 and the HPE Security Bulletin Library for detailed information about the vulnerability and available updates.
*   Apply the recommended updates for HPE Unified OSS Console (UOC) version 3.1.20 and prior to mitigate the vulnerability.
*   Deploy the Sigma rule titled "Detect Suspicious Process Creation by HPE UOC" to monitor for potential exploitation attempts on the UOC server based on unusual processes spawned.
*   Monitor network traffic originating from the HPE Unified OSS Console (UOC) server for any suspicious activity, such as connections to unusual destinations, as potential indicators of compromise.
