---
title: ExactMetrics WordPress Plugin Vulnerability Leads to Remote Code Execution
slug: 2024-01-02-exactmetrics-rce
description: The ExactMetrics plugin for WordPress is vulnerable to unauthorized arbitrary plugin installation and activation via a REST API endpoint, potentially leading to remote code execution by authenticated attackers.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - rce
  - cve-2026-5464
  - exactmetrics
vendors:
  - WordPress
products:
  - ExactMetrics – Google Analytics Dashboard for WordPress (Website Stats Plugin)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5464
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5464
rules:
  - title: Detect ExactMetrics Plugin Installation via AJAX Endpoint
    description: Detects attempts to install plugins via the exactmetrics_connect_process AJAX endpoint, which is vulnerable to arbitrary plugin installation in ExactMetrics versions up to 9.1.2.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to ExactMetrics Onboarding Connect URL
    description: Detects access to the ExactMetrics onboarding connect URL, potentially indicating an attempt to retrieve the OTH token for unauthorized plugin installation.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-5464, exists in the ExactMetrics – Google Analytics Dashboard for WordPress (Website Stats Plugin) plugin, affecting all versions up to and including 9.1.2. The vulnerability allows authenticated attackers with Editor-level access or higher, who also possess the 'exactmetrics_view_dashboard' capability, to install and activate arbitrary WordPress plugins from attacker-controlled URLs. This is possible due to the exposure of the 'onboarding_key' transient and the lack of proper authorization checks on the 'exactmetrics_connect_process' AJAX endpoint. Successful exploitation can lead to Remote Code Execution (RCE) on the target WordPress site. This poses a significant risk to websites using the vulnerable plugin, as attackers can inject malicious code and gain full control of the affected system.

## Attack Chain

1. An attacker gains authenticated access to a WordPress site as an Editor or Administrator.
2. The attacker obtains the 'onboarding_key' by accessing the reports page, which exposes the transient value to users with the 'exactmetrics_view_dashboard' capability.
3. The attacker uses the 'onboarding_key' to access the '/wp-json/exactmetrics/v1/onboarding/connect-url' REST endpoint, receiving a one-time hash (OTH) token.
4. The attacker crafts a malicious plugin ZIP file hosted on an attacker-controlled server.
5. The attacker sends a request to the 'exactmetrics_connect_process' AJAX endpoint, providing the OTH token and the URL of the malicious plugin ZIP file via the 'file' parameter. This endpoint lacks capability checks and nonce verification.
6. The ExactMetrics plugin downloads the malicious plugin ZIP file from the attacker-controlled URL.
7. The ExactMetrics plugin installs and activates the malicious plugin.
8. The attacker gains Remote Code Execution on the WordPress server through the installed malicious plugin.

## Impact

Successful exploitation of CVE-2026-5464 allows attackers to install arbitrary plugins on vulnerable WordPress sites, leading to Remote Code Execution. This grants the attacker complete control over the compromised website, enabling them to inject malicious code, deface the site, steal sensitive data, or use the site for further malicious activities. The number of affected websites depends on the widespread use of the ExactMetrics plugin. Organizations using this plugin are at risk of significant data breaches and reputational damage.

## Recommendation

*   Upgrade the ExactMetrics – Google Analytics Dashboard for WordPress (Website Stats Plugin) plugin to the latest version, which patches CVE-2026-5464.
*   Monitor web server logs for suspicious requests to the '/wp-json/exactmetrics/v1/onboarding/connect-url' REST endpoint and the 'exactmetrics_connect_process' AJAX endpoint. Implement the Sigma rule provided below to detect exploitation attempts.
*   Implement strong password policies and multi-factor authentication to prevent unauthorized access to WordPress accounts.
*   Restrict the 'exactmetrics_view_dashboard' capability to only the necessary users.
