---
title: Cisco ACI Multi-Site CloudSec Encryption Information Disclosure Vulnerability
slug: 2024-01-cisco-aci-cloudsec
description: A vulnerability in Cisco ACI Multi-Site CloudSec encryption allows a remote attacker to read or modify intersite encrypted traffic due to a flaw in cipher implementation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2023-20185
  - information-disclosure
  - network
vendors:
  - Cisco
products:
  - Nexus 9000 Series Fabric Switches in ACI mode
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2023-20185
    cvss: 7.4
    epss: 0.00174
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aci-cloudsec-enc-Vs5Wn2sX
rules:
  - title: Detect Intercepted Encrypted Traffic
    description: Detects unusual amounts of traffic between ACI sites, indicating possible interception.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - windows
  - title: Detect Potential Data Modification
    description: Detects unexpected traffic patterns that may be caused by the alteration of traffic.
    platform: sigma
    severity: medium
    tactics:
      - integrity
    techniques:
      - T1565
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A vulnerability exists within the Cisco ACI Multi-Site CloudSec encryption feature of Cisco Nexus 9000 Series Fabric Switches when operating in ACI mode. This flaw enables an unauthenticated, remote adversary to potentially decipher and manipulate encrypted traffic traversing between sites. The vulnerability, identified as CVE-2023-20185, originates from an issue in the cipher implementation employed by the CloudSec encryption feature. Cisco has deprecated and removed the affected ACI Multi-Site CloudSec encryption feature.

## Attack Chain

1.  Attacker establishes a network position on-path between ACI sites.
2.  The attacker intercepts intersite encrypted traffic.
3.  The attacker analyzes the captured traffic.
4.  The attacker exploits the weak cipher implementation.
5.  The attacker decrypts the intercepted traffic.
6.  The attacker reads sensitive data within the decrypted traffic.
7.  The attacker modifies the decrypted traffic.
8.  The attacker re-encrypts (or forwards unencrypted) the modified traffic toward the destination.

## Impact

Successful exploitation of CVE-2023-20185 allows unauthorized reading and modification of data transmitted between ACI sites. The impact can range from data breaches and intellectual property theft to manipulated financial transactions and compromised control systems. The lack of a workaround necessitates immediate action to mitigate the risk.

## Recommendation

*   Apply configuration changes to remove usage of the CloudSec encryption feature.
*   Monitor network traffic for unusual patterns indicative of man-in-the-middle attacks targeting intersite communication.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts targeting intersite traffic.
