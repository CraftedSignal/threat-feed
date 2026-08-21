---
title: Critical Vulnerabilities in Synacor Zimbra Collaboration
slug: 2026-08-zimbra-vulnerabilities
description: Synacor Zimbra Collaboration versions prior to 10.1.20 are vulnerable to multiple flaws, including actively exploited RCE (CVE-2026-73570), SSRF, and XSS, posing a high risk of unauthorized system access.
date: "2026-08-19T16:32:03Z"
lastmod: "2026-08-21T04:31:37Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=E916591B-C14B-5306-94C6-AD54D4C16C1D&utm_source=rss&utm_medium=rss
vendors:
  - Synacor
products:
  - Zimbra Collaboration
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Some of these [vulnerabilities] allow an attacker to cause remote arbitrary code execution, server-side request forgery (SSRF), and remote indirect code injection (XSS).
    confidence_band: high
cves:
  - id: CVE-2026-73570
    cvss: 8.9
    epss: 0.00539
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1041/
  - https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories
  - https://euvd.enisa.europa.eu/vulnerability/CVE-2026-73570
  - https://www.cve.org/CVERecord?id=CVE-2026-10631
  - https://www.cve.org/CVERecord?id=CVE-2026-50054
  - https://www.cve.org/CVERecord?id=CVE-2026-50055
  - https://www.cve.org/CVERecord?id=CVE-2026-73570
  - https://www.securityweek.com/hackers-target-zimbra-servers-in-active-exploitation-campaign/
  - https://sploitus.com/exploit?id=E916591B-C14B-5306-94C6-AD54D4C16C1D&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-08-21T04:31:37Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=E916591B-C14B-5306-94C6-AD54D4C16C1D&utm_source=rss&utm_medium=rss
---

Security researchers and the French national cybersecurity agency (ANSSI) have disclosed multiple vulnerabilities affecting Synacor Zimbra Collaboration versions prior to 10.1.20. These flaws include remote code execution (RCE), server-side request forgery (SSRF), and cross-site scripting (XSS). Notably, the vulnerability tracked as CVE-2026-73570 is currently being actively exploited in the wild, according to ENISA. Organizations running legacy or unpatched instances of Zimbra Collaboration are at significant risk of total system compromise, data exfiltration, or lateral movement via the exploited services. Patching to version 10.1.20 or later is the only remediation path provided by the vendor.

## Impact

Successful exploitation of these vulnerabilities allows unauthenticated or authenticated attackers to execute arbitrary code on the underlying mail server, pivot into internal network infrastructure via SSRF, or conduct session hijacking through XSS. The active exploitation of CVE-2026-73570 significantly increases the risk for organizations with internet-facing Zimbra nodes, potentially leading to widespread account takeovers and infrastructure compromise.

## Recommendation

* Immediately upgrade all instances of Zimbra Collaboration to version 10.1.20 or later to mitigate CVE-2026-73570, CVE-2026-10631, CVE-2026-50054, and CVE-2026-50055.
* Monitor webserver access logs for anomalous requests to Zimbra endpoints that deviate from established baselines for mail and administrative interface traffic.
* Audit firewall configurations to ensure that the Zimbra server does not have unnecessary outbound access to internal network segments, limiting the impact of potential SSRF exploitation.
* Review all post-patch logs for signs of persistence, such as unauthorized service accounts or unexpected web shell files in known Zimbra directories.
