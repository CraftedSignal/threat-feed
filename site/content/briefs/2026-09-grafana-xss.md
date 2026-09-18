---
title: Cross-Site Scripting Vulnerability in Grafana Geomap MapLibre
slug: 2026-09-grafana-xss
description: Grafana OSS versions 12.x and 13.x contain a cross-site scripting (XSS) vulnerability (CVE-2026-76154) in the Geomap MapLibre component that could allow attackers to execute malicious scripts in a user's session.
date: "2026-09-18T19:53:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:grafana:oss:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - security-advisory
vendors:
  - Grafana
products:
  - Grafana OSS (12.3.0 to 12.4.10, 13.0.0 to 13.0.8, 13.1.0 to 13.1.5, 13.2.0 to 13.2.1)
cves:
  - id: CVE-2026-76154
    cvss: 7.3
references:
  - https://cyber.gc.ca/en/alerts-advisories/grafana-security-advisory-av26-936
  - https://grafana.com/security/security-advisories/cve-2026-76154/
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade all affected Grafana OSS instances to the latest secure version.
      owner: IT Operations
      due: 48h
      evidence: The Cyber Centre encourages users and administrators to review the provided web links and apply any necessary updates as they become available.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Grafana OSS to the latest version per vendor security advisory.
      owner: IT Operations
      addresses: CVE-2026-76154
      evidence: Grafana security advisory (AV26-936)
---

On September 17, 2026, the Cyber Centre reported multiple vulnerabilities affecting various versions of Grafana OSS. The most critical issue identified is CVE-2026-76154, a cross-site scripting (XSS) vulnerability located within the Geomap MapLibre component. This vulnerability poses a significant risk to organizations, as a successful exploit allows an unauthorized party to execute malicious JavaScript within the context of an authenticated user's session. Depending on the user's role and permissions, this could lead to sensitive data theft, session hijacking, or the performance of unauthorized administrative actions within the Grafana instance. Affected versions include 12.3.0 through 12.4.10, 13.0.0 through 13.0.8, 13.1.0 through 13.1.5, and 13.2.0 through 13.2.1. Given the potential impact on data integrity and user account security, administrators should prioritize updating to the latest secure version of Grafana.

## Impact

Successful exploitation of CVE-2026-76154 enables attackers to bypass intended security controls by executing arbitrary client-side code. This can lead to full account takeover for authenticated users, unauthorized access to dashboard data, or the redirection of users to malicious infrastructure. The vulnerability impacts any organization relying on Grafana for operational monitoring and visualization, potentially exposing internal infrastructure data if the attacker gains administrative control.

## Recommendation

Prioritize patching all affected Grafana OSS instances to the latest available version provided by Grafana. Review all active user sessions for suspicious activity and consider implementing stricter Content Security Policy (CSP) headers to mitigate potential XSS impacts. Monitor web access logs for unusual requests targeting the Geomap or MapLibre components as potential indicators of probing or exploitation attempts.
