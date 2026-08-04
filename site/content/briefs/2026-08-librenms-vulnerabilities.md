---
title: Multiple Vulnerabilities in LibreNMS
slug: 2026-08-librenms-vulnerabilities
description: LibreNMS versions prior to 26.5.0 are affected by multiple vulnerabilities including RCE, SSRF, and XSS, posing a significant risk for unauthorized system access and network reconnaissance.
date: "2026-08-04T13:37:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - vulnerability
  - rce
  - ssrf
  - xss
vendors:
  - LibreNMS
products:
  - LibreNMS (< 26.5.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: De multiples vulnérabilités ont été découvertes dans LibreNMS. Elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance, une falsification de requêtes côté serveur (SSRF) et une injection de code indirecte à distance (XSS).
    confidence_band: high
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0966/
  - https://github.com/librenms/librenms/security/advisories/GHSA-7cj5-v4pp-v632
  - https://github.com/librenms/librenms/security/advisories/GHSA-7gww-x7fh-jf9j
  - https://github.com/librenms/librenms/security/advisories/GHSA-7hmq-j399-mqwf
  - https://github.com/librenms/librenms/security/advisories/GHSA-g993-wffj-m3gv
  - https://github.com/librenms/librenms/security/advisories/GHSA-jf24-8g2h-2wg7
  - https://github.com/librenms/librenms/security/advisories/GHSA-jmqm-f8q4-v7wx
  - https://github.com/librenms/librenms/security/advisories/GHSA-v5jp-f342-234h
  - https://www.cve.org/CVERecord?id=CVE-2026-45694
---

The French National Cybersecurity Agency (ANSSI) has published a security advisory detailing multiple vulnerabilities found within the LibreNMS network monitoring platform. The affected software includes all versions prior to 26.5.0. These vulnerabilities enable remote attackers to execute arbitrary code, perform server-side request forgery (SSRF), and conduct remote cross-site scripting (XSS) attacks. Seven specific GitHub security advisories (GHSA-7cj5-v4pp-v632, GHSA-7gww-x7fh-jf9j, GHSA-7hmq-j399-mqwf, GHSA-g993-wffj-m3gv, GHSA-jf24-8g2h-2wg7, GHSA-jmqm-f8q4-v7wx, and GHSA-v5jp-f342-234h) and CVE-2026-45694 have been identified as part of this release. These flaws present a critical risk to network administrators using the platform, as successful exploitation could lead to full system compromise or facilitate further attacks against internal network resources.

## Impact

The impact of these vulnerabilities is significant, as LibreNMS is typically deployed in privileged network segments to perform network monitoring and management. If exploited, an attacker could achieve remote code execution to gain control over the monitoring server, use the server as a pivot point for network exploitation via SSRF, or conduct XSS attacks to compromise administrative user sessions. Organizations utilizing LibreNMS versions earlier than 26.5.0 should consider these instances at high risk of compromise until updated.

## Recommendation

Prioritize the immediate upgrade of all LibreNMS installations to version 26.5.0 or higher. Security operations teams should audit network traffic originating from LibreNMS servers to detect unauthorized scanning or outbound requests characteristic of SSRF exploitation. Verify patch application for all identified affected products.
