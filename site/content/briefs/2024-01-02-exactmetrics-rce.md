---
title: ExactMetrics WordPress Plugin Vulnerability Leads to Remote Code Execution
slug: 2024-01-02-exactmetrics-rce
description: The ExactMetrics plugin for WordPress is vulnerable to unauthorized arbitrary plugin installation and activation via a REST API endpoint, potentially leading to remote code execution by authenticated attackers.
date: "2024-01-02T12:00:00Z"
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

A critical vulnerability, CVE-2026-5464, exists in the ExactMetrics – Google Analytics Dashboard for WordPress (Website Stats Plugin) plugin, affecting all versions up to and including 9.1.2. The vulnerability allows authenticated attackers with Editor-level access or higher, who also possess the 'exactmetrics_view_dashboard' capability, to install and activate arbitrary WordPress plugins from attacker-controlled URLs. This is possible due to the exposure of the 'onboarding_key' transient and…
