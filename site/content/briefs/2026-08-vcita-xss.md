---
title: Stored XSS in Online Booking & Scheduling Calendar for WordPress by vcita
slug: 2026-08-vcita-xss
description: A stored cross-site scripting (XSS) vulnerability in the vcita WordPress plugin up to version 4.6.0 allows unauthenticated attackers to inject arbitrary scripts via the 'business_id' parameter.
date: "2026-08-15T04:16:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - wordpress
vendors:
  - vcita
products:
  - Online Booking & Scheduling Calendar for WordPress by vcita
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-14433
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14433
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/3fbfb185-d901-4789-9a13-137f72234ed4?source=cve
rules:
  - title: Detect CVE-2026-14433 Exploitation Attempt - XSS in business_id parameter
    description: Detects potential exploitation of CVE-2026-14433 by identifying common XSS payloads within the business_id parameter in web requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit WordPress site plugins and update vcita booking plugin
      owner: IT Operations
      due: 48h
      evidence: Plugin vulnerable in all versions up to and including 4.6.0
  hunt_leads:
    - lead: Search web logs for requests containing script tags targeting common WordPress parameters
      technique_id: T1190
      data_needed:
        - web_server_logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Stored XSS vulnerabilities are commonly exploited for session hijacking
  mitigation_plan:
    - priority: immediate
      action: Enable WAF rules blocking suspicious XSS patterns
      owner: IT Operations
      addresses: CVE-2026-14433
      evidence: Vulnerability allows injection of arbitrary scripts via business_id
---

The 'Online Booking & Scheduling Calendar for WordPress by vcita' plugin is vulnerable to stored cross-site scripting (XSS) in all versions up to and including 4.6.0 (CVE-2026-14433). The vulnerability arises from insufficient input sanitization and output escaping on the 'business_id' parameter. This flaw allows an unauthenticated attacker to inject malicious JavaScript into the application, which is then stored and subsequently executed in the browser of any user who views the page where the injected content is rendered. Given the plugin's role in booking and scheduling, this could be leveraged for session hijacking, unauthorized actions on behalf of site administrators, or redirecting site visitors to malicious domains.

## Attack Chain

1. Attacker identifies an instance of the 'Online Booking & Scheduling Calendar for WordPress by vcita' plugin.
2. Attacker crafts an HTTP request containing a malicious JavaScript payload within the 'business_id' parameter.
3. The plugin fails to sanitize the 'business_id' input before processing or storing it.
4. The malicious payload is saved into the WordPress database.
5. A victim user (e.g., administrator or site customer) navigates to the compromised web page.
6. The web server renders the stored, unsanitized payload into the HTML response.
7. The victim's browser executes the injected JavaScript script in the context of the vulnerable site.
8. Attacker achieves execution of arbitrary code within the victim's browser session.

## Impact

Successful exploitation of CVE-2026-14433 can lead to the compromise of user sessions, allowing attackers to perform unauthorized actions as the victim. If an administrator is targeted, this could lead to full site compromise, including the modification of site content, exfiltration of sensitive booking data, or redirection of traffic.

## Recommendation

* Update the 'Online Booking & Scheduling Calendar for WordPress by vcita' plugin to the latest version available (patch versions beyond 4.6.0).
* Implement a Content Security Policy (CSP) to mitigate the impact of XSS attacks by restricting the execution of inline scripts and unauthorized external resources.
* Monitor web application logs for HTTP requests containing abnormal character strings (e.g., '&lt;script>', 'javascript:', 'onerror=') within parameter values.
* Utilize a Web Application Firewall (WAF) to inspect and block malicious payloads targeting the 'business_id' parameter.
