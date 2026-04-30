---
title: UniFi Play Improper Access Control Vulnerability (CVE-2026-22566)
slug: 2026-04-unifi-play-access-control
description: An improper access control vulnerability in UniFi Play PowerAmp and Audio Port allows a malicious actor with access to the UniFi Play network to obtain WiFi credentials.
date: "2026-04-13T22:16:28Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - vulnerability
  - access-control
  - unifi
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1558
    technique_name: Steal or Forge Credentials
cves:
  - id: CVE-2026-22566
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22566
  - https://community.ui.com/releases/Security-Advisory-Bulletin-063/e468dd4b-5090-4ef8-89d8-939903c08e83
rules:
  - title: Detect UniFi Play Device Network Activity
    description: Detect network connections originating from UniFi Play devices after CVE-2026-22566 disclosure.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1558
    data_sources:
      - network_connection
      - windows
  - title: Detect Vulnerable UniFi Play PowerAmp Version
    description: Detects vulnerable versions of UniFi Play PowerAmp based on file metadata
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1558
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-22566 describes an improper access control vulnerability affecting UniFi Play devices. Specifically, UniFi Play PowerAmp (version 1.0.35 and earlier) and UniFi Play Audio Port (version 1.0.24 and earlier) are vulnerable. A malicious actor who has already gained access to the UniFi Play network can exploit this vulnerability to obtain UniFi Play WiFi credentials. This vulnerability was reported by HackerOne and assigned a CVSS v3.1 base score of 7.5. The vulnerability was published on April 13, 2026. Updating the affected devices to the specified fixed versions is recommended to mitigate the risk.

## Attack Chain

1. The attacker gains initial access to the UniFi Play network. (This step is a prerequisite and not detailed in the advisory)
2. The attacker leverages an access control flaw in the UniFi Play PowerAmp or Audio Port software.
3. A specially crafted request is sent to the vulnerable device via the local network.
4. The vulnerable device improperly handles the access control check.
5. The device divulges the stored WiFi credentials.
6. The attacker captures the exposed WiFi credentials.
7. The attacker uses the WiFi credentials to gain broader access to the wireless network.

## Impact

Successful exploitation of CVE-2026-22566 allows an attacker with existing access to a UniFi Play network to obtain WiFi credentials. This could lead to unauthorized access to the wireless network, potentially compromising other devices and sensitive information on the network. While the specific number of affected users is unknown, any network utilizing vulnerable versions of UniFi Play PowerAmp or Audio Port is at risk. The impact is elevated if the compromised WiFi network provides access to critical infrastructure or sensitive data.

## Recommendation

*   Immediately update UniFi Play PowerAmp to version 1.0.38 or later and UniFi Play Audio Port to version 1.1.9 or later to remediate CVE-2026-22566.
*   Monitor network traffic for suspicious activity originating from UniFi Play devices after the vulnerability was disclosed (2026-04-13).
*   Segment the UniFi Play network from other critical networks to limit the impact of a potential breach.
*   Implement network access control policies to restrict access to sensitive resources from the UniFi Play network, even after applying the patch.
