---
title: Multiple Vulnerabilities in GitLab CE/EE Allow for Arbitrary Code Execution, Data Confidentiality Compromise, and SSRF
slug: 2026-05-multiple-gitlab-vulnerabilities
description: Multiple vulnerabilities in GitLab Community Edition (CE) and Enterprise Edition (EE) can allow an attacker to perform arbitrary code execution, compromise data confidentiality, perform server-side request forgery (SSRF), and other security breaches.
date: "2026-05-15T12:24:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - gitlab
  - vulnerability
  - rce
  - ssrf
  - xss
  - csrf
vendors:
  - GitLab
products:
  - GitLab Community Edition (CE)
  - GitLab Enterprise Edition (EE)
cves:
  - id: CVE-2025-13874
    cvss: 4.3
    epss: 0.0001
  - id: CVE-2025-14870
    cvss: 7.5
    epss: 0.00038
  - id: CVE-2026-1338
    cvss: 4.3
    epss: 0.0001
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0593/
  - https://docs.gitlab.com/releases/patches/patch-release-gitlab-18-11-3-released/
  - https://www.cve.org/CVERecord?id=CVE-2025-12669
  - https://www.cve.org/CVERecord?id=CVE-2025-13874
  - https://www.cve.org/CVERecord?id=CVE-2025-14869
  - https://www.cve.org/CVERecord?id=CVE-2025-14870
  - https://www.cve.org/CVERecord?id=CVE-2026-1184
  - https://www.cve.org/CVERecord?id=CVE-2026-1322
  - https://www.cve.org/CVERecord?id=CVE-2026-1338
  - https://www.cve.org/CVERecord?id=CVE-2026-1659
  - https://www.cve.org/CVERecord?id=CVE-2026-2900
  - https://www.cve.org/CVERecord?id=CVE-2026-3073
  - https://www.cve.org/CVERecord?id=CVE-2026-3074
  - https://www.cve.org/CVERecord?id=CVE-2026-3160
  - https://www.cve.org/CVERecord?id=CVE-2026-3607
  - https://www.cve.org/CVERecord?id=CVE-2026-4524
  - https://www.cve.org/CVERecord?id=CVE-2026-4527
  - https://www.cve.org/CVERecord?id=CVE-2026-5297
  - https://www.cve.org/CVERecord?id=CVE-2026-6063
  - https://www.cve.org/CVERecord?id=CVE-2026-6073
  - https://www.cve.org/CVERecord?id=CVE-2026-6335
  - https://www.cve.org/CVERecord?id=CVE-2026-6883
  - https://www.cve.org/CVERecord?id=CVE-2026-7377
  - https://www.cve.org/CVERecord?id=CVE-2026-7471
  - https://www.cve.org/CVERecord?id=CVE-2026-7481
  - https://www.cve.org/CVERecord?id=CVE-2026-8144
  - https://www.cve.org/CVERecord?id=CVE-2026-8280
rules:
  - title: Detect Suspicious POST Requests to GitLab Endpoints with Shell Metacharacters
    description: Detects HTTP POST requests to common GitLab endpoints containing shell metacharacters, which may indicate command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect GitLab User Impersonation via Cookie Manipulation
    description: Detects potential GitLab user impersonation attempts by monitoring for unusual patterns in session cookies, such as modification or replacement.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

On May 15, 2026, CERT-FR published an advisory regarding multiple vulnerabilities found in GitLab Community Edition (CE) and Enterprise Edition (EE). These vulnerabilities, detailed in the GitLab security bulletin released on May 13, 2026, pose significant risks, including arbitrary code execution, data confidentiality compromise, server-side request forgery (SSRF), cross-site scripting (XSS), and cross-site request forgery (CSRF). The advisory highlights the importance of applying necessary patches to mitigate potential exploits targeting these weaknesses. The affected versions include GitLab CE and EE versions 18.10.x before 18.10.6, versions 18.11.x before 18.11.3, and versions prior to 18.9.7. Successful exploitation of these vulnerabilities could lead to significant damage, including unauthorized access to sensitive information and complete system compromise.

## Attack Chain

1.  An attacker identifies a vulnerable GitLab instance running a version prior to the patched releases (18.10.6, 18.11.3, or 18.9.7).
2.  The attacker crafts a malicious request targeting one of the identified vulnerabilities (e.g., SSRF via CVE-2026-XXXX or arbitrary code execution via CVE-2025-XXXX).
3.  The attacker sends the crafted request to the vulnerable GitLab instance, potentially exploiting an exposed API endpoint or web interface.
4.  If the vulnerability is an SSRF, the attacker may be able to scan internal networks or access internal resources otherwise inaccessible from the outside.
5.  If the vulnerability leads to arbitrary code execution, the attacker injects malicious code, such as a reverse shell, into the GitLab server.
6.  The injected code executes with the privileges of the GitLab application, allowing the attacker to gain control of the server.
7.  The attacker establishes a persistent connection to the compromised server.
8.  The attacker moves laterally within the network, escalating privileges and gaining access to sensitive data.

## Impact

Successful exploitation of these vulnerabilities can result in a range of severe impacts. Attackers could gain unauthorized access to sensitive data stored within GitLab repositories, including source code, credentials, and confidential documents. Arbitrary code execution can allow attackers to take complete control of the GitLab server, potentially leading to data breaches, service disruption, and further lateral movement within the network. The number of affected GitLab instances is potentially very large, given its widespread use across various sectors.

## Recommendation

*   Immediately patch GitLab instances to the latest versions to address the vulnerabilities mentioned in the advisory, specifically upgrading versions 18.10.x before 18.10.6, 18.11.x before 18.11.3, and versions prior to 18.9.7 (see GitLab's security bulletin in the [Documentation](https://docs.gitlab.com/releases/patches/patch-release-gitlab-18-11-3-released/) section).
*   Monitor web server logs for suspicious activity targeting GitLab endpoints, looking for patterns indicative of exploitation attempts (e.g., unusual POST requests, specific URI patterns associated with known vulnerabilities). Deploy the provided Sigma rule detecting POST requests containing shell metacharacters to common GitLab endpoints.
*   Implement network segmentation to limit the impact of a successful SSRF attack, restricting access from the GitLab server to only necessary internal resources.
*   Review and harden GitLab's security configuration based on GitLab's security documentation, ensuring that all unnecessary services are disabled and that access controls are properly configured.
