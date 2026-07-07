---
title: Hitachi Energy PROMOD V Insecure HTTP Transmission Vulnerability (CVE-2026-10763)
slug: 2026-07-hitachi-energy-promod-v-insecure-http
description: Hitachi Energy PROMOD V versions 1.0.10 and prior are affected by CVE-2026-10763, an insecure HTTP transmission vulnerability that allows attackers to intercept or manipulate sensitive data in transit, potentially leading to credential theft, session hijacking, or unauthorized access, impacting the energy sector globally.
date: "2026-07-07T16:51:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ics
  - ot
  - vulnerability
  - http-insecurity
  - data-in-transit
  - cve
vendors:
  - Hitachi Energy
products:
  - PROMOD V <= 1.0.10
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1040
    technique_name: Network Sniffing
    evidence: This vulnerability could allow attackers to intercept or manipulate sensitive data in transit, potentially leading to credential theft, session hijacking, or unauthorized access.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: potentially leading to credential theft, session hijacking, or unauthorized access.
    confidence_band: high
cves:
  - id: CVE-2026-10763
    epss: 0.00347
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-188-02
  - https://www.cve.org/CVERecord?id=CVE-2026-10763
---

A critical vulnerability, CVE-2026-10763, has been identified in Hitachi Energy PROMOD V software, affecting versions 1.0.10 and prior. This vulnerability stems from the product's reliance on insecure HTTP communication with its third-party Digipede server, rather than encrypted HTTPS. Attackers with network access can exploit this weakness to intercept or manipulate sensitive data transmitted between the PROMOD V client and the Digipede server. Such interception could lead to credential theft, session hijacking, or unauthorized access to the PROMOD V system, posing a significant risk to industrial control systems. The vulnerability impacts the energy sector worldwide, as PROMOD V is deployed globally in critical infrastructure environments. The CISA advisory, published on 2026-07-07, highlights the need for immediate remediation.

## Attack Chain

1.  **Network Access**: An attacker gains access to the same network segment where Hitachi Energy PROMOD V clients communicate with the Digipede server. This could be achieved through various means, including compromise of a network device or insider threat.
2.  **Traffic Interception**: The attacker initiates network sniffing to monitor unencrypted HTTP traffic flowing between PROMOD V and the Digipede server.
3.  **Data Capture**: The attacker successfully captures sensitive data such as authentication credentials, session tokens, or operational parameters exchanged over the insecure HTTP connection.
4.  **Credential Theft/Session Hijacking**: Using the captured credentials or session tokens, the attacker compromises legitimate user accounts or hijacks active user sessions within the PROMOD V system.
5.  **Unauthorized Access**: The attacker leverages the stolen credentials or hijacked session to gain unauthorized access to the PROMOD V application, enabling them to view, modify, or disrupt critical energy grid operations.

## Impact

The exploitation of CVE-2026-10763 can have severe consequences for organizations utilizing Hitachi Energy PROMOD V, particularly within the energy sector. Successful attacks could result in the theft of sensitive operational data, unauthorized control over industrial processes, or significant disruption to critical infrastructure. The vulnerability's global deployment in the energy sector suggests a broad potential victim scope. The direct impact includes loss of confidentiality and integrity of data, potential for system downtime, and compromise of operational technology (OT) environments, leading to economic losses and safety risks.

## Recommendation

*   Upgrade Hitachi Energy PROMOD V to version 1.0.11 or later to remediate CVE-2026-10763, and ensure HTTPS is enabled on the Digipede server as per the vendor's guidance.
*   Implement network segmentation to isolate PROMOD V and Digipede server communications from less secure networks, limiting attacker reach as a mitigation for CVE-2026-10763.
*   Deploy firewalls with strict egress and ingress rules to protect control system networks from external threats, reducing the risk of an attacker gaining the necessary network access to exploit CVE-2026-10763.
*   Utilize Virtual Private Networks (VPNs) for any remote access to PROMOD V systems, ensuring all communication channels are encrypted to prevent data interception related to CVE-2026-10763.
