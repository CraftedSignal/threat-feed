---
title: Critical Vulnerabilities in Ebyte NA111-M Firmware
slug: 2026-08-ebyte-na111-m-vulnerabilities
description: Multiple critical vulnerabilities in Ebyte NA111-M firmware version 9013-2-17, including missing authentication and authorization bypasses, allow unauthenticated remote attackers to gain full administrative control.
date: "2026-08-27T16:05:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Ebyte
products:
  - NA111-M (Firmware 9013-2-17)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker could access sensitive configuration information, modify device settings, or disrupt availability.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A low privileged authenticated attacker could access security sensitive configuration functions and modify settings that affect the confidentiality, integrity, or availability of the device.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-239-05
  - https://www.cve.org/CVERecord?id=CVE-2026-73125
  - https://www.cve.org/CVERecord?id=CVE-2026-76179
  - https://www.cve.org/CVERecord?id=CVE-2026-75814
  - https://www.cve.org/CVERecord?id=CVE-2026-76940
  - https://www.cve.org/CVERecord?id=CVE-2026-77966
  - https://www.cve.org/CVERecord?id=CVE-2026-73809
  - https://www.cve.org/CVERecord?id=CVE-2026-71187
  - https://www.cve.org/CVERecord?id=CVE-2026-75548
  - https://www.cve.org/CVERecord?id=CVE-2026-69658
  - https://www.cve.org/CVERecord?id=CVE-2026-76133
  - https://www.cve.org/CVERecord?id=CVE-2026-73819
  - https://www.cve.org/CVERecord?id=CVE-2026-77975
  - https://www.cve.org/CVERecord?id=CVE-2026-77977
---

Ebyte NA111-M devices running firmware version 9013-2-17 are affected by a collection of thirteen critical security vulnerabilities. These flaws, which include missing authentication for critical functions, improper token management, and lack of authentication rate limiting, expose the device to full compromise by unauthenticated remote attackers. An adversary can exploit these weaknesses to access sensitive configuration data, modify system settings, or cause a denial-of-service condition. Because the web management interface does not consistently verify origin or privilege levels, an attacker can effectively bypass security controls to gain administrative access. The vendor has acknowledged these findings but has not released security patches to address these issues. Organizations deploying these devices globally in the Information Technology sector should take immediate steps to isolate affected hardware from the public internet.

## Attack Chain

1. An attacker identifies an internet-facing Ebyte NA111-M device via network scanning.
2. The attacker targets the web management interface using CVE-2026-73125 to gain unauthenticated access to device settings.
3. Alternatively, the attacker uses CSRF (CVE-2026-75814) by tricking an administrator into interacting with a malicious link to trigger unauthorized configuration changes.
4. The attacker performs brute-force or credential-stuffing attacks against the management portal, aided by the lack of rate limiting (CVE-2026-76940).
5. The attacker intercepts or steals session tokens due to improper client-side protection (CVE-2026-76179) to impersonate legitimate administrative sessions.
6. The attacker leverages the lack of function separation (CVE-2026-77966) to escalate from a low-privileged user to full administrative rights.
7. Final objectives include device exfiltration of sensitive configuration data or complete disruption of service.

## Impact

Successful exploitation results in full administrative control over the Ebyte NA111-M device. This allows for the compromise of internal network information, modification of device behavior, and persistent denial-of-service, impacting organizations that rely on these gateways for IT operations.

## Recommendation

* Isolate the Ebyte NA111-M web management interface from the public internet to mitigate unauthorized access.
* Monitor webserver logs for high-frequency requests from single source IPs to the device management interface, signaling potential brute-force attempts (CVE-2026-76940).
* Block unauthorized access to the device management interface at the perimeter firewall, permitting only known administrative IP ranges.
* Contact Ebyte support for status updates regarding pending security patches for the 9013-2-17 firmware.
