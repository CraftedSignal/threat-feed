---
brief_id: brief-2026-06-checkpoint-ikev1-improper-auth
event_id: brief-2026-06-checkpoint-ikev1-improper-auth
revision: 2
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:afd466cc8e73aade8e2c60201aa475fc9d5c5494e9aad82150a5f2430db0bbdd
    summary: exploited:true; KEV CVE-2026-50751; KEV CVE-2024-24919
    changed_fields:
      - affected_products
      - cpes
      - cves
      - exploitation_evidence
      - has_poc
      - iocs
      - lastmod
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Check Point Security Gateway IKEv1 Improper Authentication Vulnerability (CVE-2026-50751)
slug: 2026-06-checkpoint-ikev1-improper-auth
description: An unauthenticated remote attacker can exploit an improper authentication vulnerability (CVE-2026-50751) in Check Point Security Gateway's IKEv1 key exchange to bypass user authentication and establish a remote access VPN connection without a valid password, leading to unauthorized network access and potential ransomware deployment.
date: "2026-06-14T08:55:45Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2024-05-30T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:checkpoint:cloudguard_network_security:r80.40:*:*:*:*:*:*:*
  - cpe:2.3:a:checkpoint:cloudguard_network_security:r81.10:*:*:*:*:*:*:*
  - cpe:2.3:a:checkpoint:cloudguard_network_security:r81.20:*:*:*:*:*:*:*
  - cpe:2.3:a:checkpoint:cloudguard_network_security:r81:*:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:*:*:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:-:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_101:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_103:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_105:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_10:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_111:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_113:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_115:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_118:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_119:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_120:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_122:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_126:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_127:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_141:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_14:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_24:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_26:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:gaia_os:r81.20:take_38:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:quantum_security_gateway_firmware:r80.40:*:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:quantum_security_gateway_firmware:r81.10:*:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:quantum_security_gateway_firmware:r81.20:*:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:quantum_security_gateway_firmware:r81:*:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:quantum_spark_firmware:r80.20:*:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:quantum_spark_firmware:r80.40:*:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:quantum_spark_firmware:r81.10:*:*:*:*:*:*:*
  - cpe:2.3:o:checkpoint:quantum_spark_firmware:r81:*:*:*:*:*:*:*
has_poc: true
tags:
  - authentication-bypass
  - vpn
  - network-device
  - cisa-kev
  - ransomware
vendors:
  - Check Point
products:
  - Mobile Access
  - R80.20.X
  - R80.40
  - R81
  - R81.10
  - R81.10.X
  - R81.20
  - R82
  - R82.00.X
  - R82.10
  - Remote Access VPN
  - Security Gateway
  - Spark Firewall
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
cves:
  - id: CVE-2026-50751
    cvss: 9.3
    epss: 0.11841
    kev: true
    kev_status: "true"
  - id: CVE-2026-50752
    cvss: 7.4
    epss: 0.00031
    kev_status: unknown
  - id: CVE-2024-24919
    cvss: 8.6
    epss: 0.94342
    kev: true
    kev_status: "true"
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-50751
  - https://blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol/
  - https://support.checkpoint.com/results/sk/sk185033?_gl=1*1wqeqhc*_gcl_au*MTI1MzE5MjI2LjE3ODA5MzQ1NTM.
  - https://nvd.nist.gov/vuln/detail/CVE-2026-50751
  - https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751
iocs:
  - type: ip
    value: 45.77.149.152
  - type: ip
    value: 209.182.225.136
  - type: ip
    value: 38.60.157.139
  - type: ip
    value: 162.33.177.101
  - type: ip
    value: 45.76.26.42
  - type: ip
    value: 144.208.127.155
  - type: ip
    value: 38.54.88.201
  - type: ip
    value: 38.54.107.167
  - type: ip
    value: 66.42.99.200
  - type: hash_md5
    value: 52fda5c1b9704544f32ee98d9060e689
  - type: hash_md5
    value: 51d39aa39478beeac94f2d12f682ecce
ioc_counts:
  hash_md5: 2
  ip: 9
rules:
  - title: Detects CVE-2026-50751 Exploitation — Check Point Successful IKEv1 VPN Connection
    description: Detects CVE-2026-50751 exploitation — Monitors Check Point Security Gateway logs for successful VPN connections utilizing the deprecated and vulnerable IKEv1 protocol, which could indicate an authentication bypass. This rule is most effective if IKEv1 is intended to be disabled.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - firewall
      - checkpoint
rules_count: 1
updates:
  - at: "2026-06-14T09:05:21Z"
    level: L2
    summary: poc_available; added CVE-2024-24919 +1
    sources:
      - rapid7
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-50751; KEV CVE-2024-24919
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Check Point Security Gateway is vulnerable to an improper authentication flaw, tracked as CVE-2026-50751, residing within its IKEv1 key exchange mechanism. This critical vulnerability allows an unauthenticated remote attacker to completely bypass user authentication. By exploiting this flaw, attackers can establish a remote access VPN connection to the targeted network without requiring a valid user password. The vulnerability is particularly severe as it affects a deprecated protocol, IKEv1, yet it can still be enabled on vulnerable Security Gateway devices. Its inclusion in the CISA Known Exploited Vulnerabilities (KEV) Catalog, coupled with confirmed use in ransomware campaigns, underscores the urgency for immediate mitigation to prevent unauthorized network access and subsequent malicious activities.

## Attack Chain

1.  **Reconnaissance & Vulnerability Identification:** An attacker scans for internet-facing Check Point Security Gateway devices and identifies instances with the deprecated IKEv1 protocol enabled.
2.  **IKEv1 Key Exchange Initiation:** The attacker initiates an IKEv1 key exchange process with the vulnerable Check Point Security Gateway.
3.  **Exploitation of Improper Authentication:** The attacker exploits the CVE-2026-50751 vulnerability during the IKEv1 key exchange phase.
4.  **Authentication Bypass:** Due to the flaw, the Security Gateway's authentication process is bypassed, allowing the attacker to proceed without providing valid user credentials.
5.  **Establishment of Remote Access VPN:** The attacker successfully establishes a remote access VPN connection to the internal network as an unauthenticated user.
6.  **Internal Network Access:** With VPN access, the attacker gains a foothold in the target organization's internal network.
7.  **Post-Exploitation Activities:** The attacker proceeds with internal network reconnaissance, lateral movement, data exfiltration, or deployment of ransomware and other malware, leveraging their unauthorized access.
8.  **Impact:** The attacker achieves their final objective, which could include data theft, system disruption, or encryption of systems via ransomware.

## Impact

The successful exploitation of CVE-2026-50751 grants an unauthenticated remote attacker full unauthorized access to an organization's internal network via a remote access VPN connection. This access can lead to severe consequences, including the exfiltration of sensitive data, deployment of ransomware (as evidenced by its known use in such campaigns), and significant disruption of business operations. Organizations in any sector using Check Point Security Gateway with IKEv1 enabled are at risk. The vulnerability's presence in the CISA KEV catalog highlights its critical nature and confirmed in-the-wild exploitation.

## Recommendation

*   Immediately apply hotfix sk185033 from Check Point on all affected Security Gateway devices.
*   Disable the deprecated IKEv1 VPN protocol on all Check Point Security Gateways if not strictly required, as per Check Point's guidance in blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol/.
*   Deploy the Sigma rule "Detects CVE-2026-50751 Exploitation — Check Point Successful IKEv1 VPN Connection" to your SIEM to alert on any successful IKEv1 VPN connections, especially if this protocol should be disabled.
*   Enable comprehensive logging for all VPN connection attempts and successes on Check Point Security Gateway devices to monitor for anomalous activity.
*   Review VPN authentication logs for successful connections from unusual source IPs or involving unexpected user accounts, using the Sigma rule "Detects CVE-2026-50751 - Check Point VPN Bruteforce Attempts" as a starting point for detection.
