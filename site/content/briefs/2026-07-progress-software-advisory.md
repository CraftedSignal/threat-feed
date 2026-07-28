---
title: Progress Software Security Advisory Addresses Multiple Vulnerabilities
slug: 2026-07-progress-software-advisory
description: Progress Software has issued a security advisory (AV26-755) addressing multiple vulnerabilities, identified by CVEs CVE-2026-59686 through CVE-2026-59690, across several of its products including ECS Connection Manager, LoadMaster, MOVEit WAF, Multi Tenant, and Object Scale Connection Manager, with specific versions prior to various patch levels being vulnerable, urging administrators to apply necessary updates to secure their systems.
date: "2026-07-28T18:52:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - cve
  - security-advisory
  - patch-management
vendors:
  - Progress Software
products:
  - ECS Connection Manager < 7.2.63.3
  - LoadMaster < 7.2.63.3
  - MOVEit WAF < 7.2.63.3
  - Multi Tenant < 7.1.35.16
  - Object Scale Connection Manager < 7.2.63.3
cves:
  - id: CVE-2026-59686
    cvss: 8.4
  - id: CVE-2026-59690
    cvss: 8
  - id: CVE-2026-59687
    cvss: 8.4
  - id: CVE-2026-59688
    cvss: 8.4
  - id: CVE-2026-59689
    cvss: 8
references:
  - https://cyber.gc.ca/en/alerts-advisories/progress-software-security-advisory-av26-755
  - https://community.progress.com/s/article/LoadMaster-Critical-Security-Bulletin-July-2026-CVE-2026-59686-CVE-2026-59687-CVE-2026-59688-CVE-2026-59689-CVE-2026-59690
---

On July 28, 2026, the Canadian Centre for Cyber Security (CCCS) issued an alert regarding a critical security advisory (AV26-755) from Progress Software. This advisory addresses multiple vulnerabilities, designated CVE-2026-59686 through CVE-2026-59690, affecting several Progress Software products. The impacted products include ECS Connection Manager, LoadMaster, MOVEit WAF, Multi Tenant, and Object Scale Connection Manager, specifically versions prior to 7.2.63.3, and Multi Tenant prior to 7.1.35.16. While specific details on the nature of these vulnerabilities are not provided in the advisory, the classification as a "Critical Security Bulletin" indicates a significant potential for compromise. Defenders should prioritize updating these systems to mitigate risks associated with potential exploitation.

## Attack Chain

This advisory describes multiple vulnerabilities and does not detail a specific attack chain or observed exploitation. Information regarding specific exploitation methods, such as initial access vectors or post-compromise actions, is not provided in the source material.

## Impact

Successful exploitation of the vulnerabilities listed in the Progress Software advisory could lead to significant security breaches, potentially resulting in unauthorized access, data compromise, denial of service, or complete system takeover, depending on the specific nature of each CVE. Organizations utilizing affected Progress Software products could face severe operational disruption, reputational damage, and regulatory penalties. The advisory does not specify the number of victims or sectors targeted, but the widespread use of these products suggests a broad potential impact across various industries if left unpatched.

## Recommendation

* Review the official Progress Customer Community advisory for detailed information on CVE-2026-59686, CVE-2026-59687, CVE-2026-59688, CVE-2026-59689, and CVE-2026-59690.
* Immediately apply all necessary updates for ECS Connection Manager, LoadMaster, MOVEit WAF, Multi Tenant, and Object Scale Connection Manager as they become available from Progress Software.
* Implement a robust vulnerability management program to identify and remediate vulnerable software versions across your environment.
* Monitor network traffic for anomalous connections originating from or destined for affected Progress Software products, which may indicate attempted or successful exploitation.
