---
title: Citrix Secure Access Client for Windows Vulnerabilities Lead to Privilege Escalation and Information Disclosure
slug: 2026-07-citrix-secure-access-privesc
description: Multiple vulnerabilities in Citrix Systems Secure Access Client for Windows can be exploited by a local attacker to achieve privilege escalation and information disclosure on affected Windows systems.
date: "2026-07-15T09:01:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - privilege-escalation
  - information-disclosure
  - windows
vendors:
  - Citrix Systems
products:
  - Secure Access Client for Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein lokaler Angreifer kann mehrere Schwachstellen in Citrix Systems Secure Access Client for Windows ausnutzen, um seine Privilegien zu erhöhen
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
    evidence: Ein lokaler Angreifer kann mehrere Schwachstellen in Citrix Systems Secure Access Client for Windows ausnutzen, um ... Informationen offenzulegen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2339
---

The German Federal Office for Information Security (BSI) has released an advisory concerning multiple vulnerabilities identified in the Citrix Systems Secure Access Client for Windows. These vulnerabilities can be exploited by a local attacker, meaning an adversary who has already gained some level of access to the target system. Successful exploitation could allow the attacker to elevate their privileges, gaining higher-level access than initially possessed, and to disclose sensitive information. While specific vulnerability details such as CVE IDs or observed exploitation campaigns are not provided in the advisory, the presence of these flaws poses a risk to systems where the Secure Access Client is installed, necessitating prompt action to prevent potential unauthorized access and data breaches.

## Impact

Successful exploitation of these vulnerabilities by a local attacker could result in significant security breaches. The primary impacts are privilege escalation, which allows an attacker to execute arbitrary code with higher permissions (e.g., SYSTEM), and information disclosure, which could lead to the exposure of sensitive data processed or stored by the client or the underlying operating system. Organizations relying on Citrix Secure Access Client for Windows for remote access or VPN capabilities are at risk, as a compromised client could serve as a foothold for broader network penetration or data exfiltration.

## Recommendation

* Apply the latest security updates provided by Citrix Systems for the Secure Access Client for Windows immediately to address the identified vulnerabilities.
* Monitor local system activity for unusual process creations, file access patterns, or network connections originating from the Citrix Secure Access Client application that could indicate attempted exploitation.
