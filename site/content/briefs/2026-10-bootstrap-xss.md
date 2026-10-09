---
title: Bootstrap Cross-Site Scripting Vulnerability
slug: 2026-10-bootstrap-xss
description: A vulnerability in the Bootstrap framework allows for Cross-Site Scripting (XSS) attacks by an unauthenticated remote attacker, potentially leading to arbitrary script execution in a user's browser.
date: "2026-10-09T13:11:43Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:getbootstrap:bootstrap:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_access_policy_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_advanced_firewall_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_analytics:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_application_acceleration_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_application_security_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_domain_name_system:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_edge_gateway:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_fraud_protection_service:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_global_traffic_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_link_controller:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_local_traffic_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_policy_enforcement_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:f5:big-ip_webaccelerator:*:*:*:*:*:*:*:*
  - cpe:2.3:a:redhat:virtualization_manager:4.3:*:*:*:*:*:*:*
  - cpe:2.3:a:tenable:tenable.sc:*:*:*:*:*:*:*:*
vendors:
  - Bootstrap
products:
  - Bootstrap (< 4.3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: A remote, anonymer Angreifer kann eine Schwachstelle in Bootstrap ausnutzen, um einen Cross-Site Scripting Angriff durchzuführen.
    confidence_band: high
cves:
  - id: CVE-2019-8331
    cvss: 6.1
    epss: 0.16404
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-1072
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8331
action_plan:
  priority: elevated
  owners:
    - Development
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Bootstrap to 4.3.1 or later
      owner: Development
      addresses: CVE-2019-8331
      evidence: Source identifies vulnerability in versions < 4.3.1
---

A security vulnerability (CVE-2019-8331) has been identified in the Bootstrap framework, specifically affecting versions prior to 4.3.1. This vulnerability allows a remote, unauthenticated attacker to conduct Cross-Site Scripting (XSS) attacks. By injecting malicious scripts into web applications that utilize vulnerable versions of Bootstrap, an attacker can execute code within the context of a victim's browser session. This can lead to session hijacking, credential theft, or the modification of web page content viewed by the user. Defenders should prioritize auditing web applications for these vulnerable versions of the Bootstrap framework and upgrade to version 4.3.1 or later to mitigate the risk.

## Impact

Successful exploitation of this XSS vulnerability allows unauthorized actors to execute arbitrary scripts in the victim's browser. This poses a significant risk to the integrity and confidentiality of user data on affected web applications, potentially facilitating session hijacking or phishing attacks against users.

## Recommendation

Prioritized actions for security and development teams:
- Audit all web applications to identify dependencies using Bootstrap versions prior to 4.3.1.
- Upgrade the Bootstrap framework to version 4.3.1 or later across all identified applications.
- Apply Content Security Policy (CSP) headers as a defense-in-depth measure to restrict the execution of unauthorized scripts.
