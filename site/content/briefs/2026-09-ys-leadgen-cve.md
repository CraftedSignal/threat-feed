---
title: Sensitive Information Exposure in YS LeadGen WordPress Plugin
slug: 2026-09-ys-leadgen-cve
description: The YS LeadGen plugin for WordPress versions 2.1.4 and earlier contains an unauthenticated information exposure vulnerability allowing the retrieval of form submission data.
date: "2026-09-19T10:11:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ys_leadgen_project:ys_leadgen:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - sensitive-information-exposure
  - wordpress
vendors:
  - WordPress
products:
  - YS LeadGen (<= 2.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: The 'ysleadgen_get_captured_data' AJAX action is accessible to unauthenticated users, allowing attackers to retrieve captured form submission data.
    confidence_band: high
cves:
  - id: CVE-2026-1255
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1255
rules:
  - title: Detect CVE-2026-1255 Exploitation - Unauthenticated AJAX Data Retrieval
    description: Detects unauthorized access to the YS LeadGen 'ysleadgen_get_captured_data' AJAX action via web server access logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Check WordPress plugin inventory for vulnerable versions of YS LeadGen
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-1255
  hunt_leads:
    - lead: Search logs for 200 responses to ysleadgen_get_captured_data from external IP addresses
      technique_id: T1592
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows retrieval of sensitive data via AJAX
  mitigation_plan:
    - priority: immediate
      action: Update YS LeadGen to version 2.1.5 or newer
      owner: IT Operations
      addresses: CVE-2026-1255
      evidence: Plugin vulnerable <= 2.1.4
---

The YS LeadGen plugin for WordPress, in all versions up to and including 2.1.4, is susceptible to a sensitive information exposure vulnerability identified as CVE-2026-1255. The vulnerability stems from the improper implementation of the 'ysleadgen_get_captured_data' AJAX action, which fails to enforce authentication checks. This oversight allows unauthenticated, remote attackers to query the action and retrieve captured lead data stored by the plugin. The exposed data includes personally identifiable information (PII) such as user names, email addresses, and the content of messages submitted through forms managed by the plugin. This flaw facilitates unauthorized access to sensitive user data, presenting a significant risk to organizations collecting leads via the YS LeadGen plugin. Defenders should monitor web server logs for unauthorized requests targeting this specific AJAX endpoint.

## Impact

The vulnerability poses a high risk to organizations using the affected versions of the YS LeadGen plugin. Successful exploitation leads to the unauthorized exfiltration of PII collected through website forms, potentially resulting in data breaches, regulatory non-compliance, and loss of user trust. Because the vulnerability is accessible to unauthenticated users, the barrier to exploitation is low.

## Recommendation

* Upgrade the YS LeadGen plugin to a version beyond 2.1.4 immediately to resolve CVE-2026-1255.
* Monitor web server logs (e.g., Apache, Nginx, or IIS access logs) for HTTP requests targeting the '/wp-admin/admin-ajax.php' path with the 'action=ysleadgen_get_captured_data' parameter from suspicious or unauthorized IP addresses.
* Review web application firewall (WAF) logs for abnormal spikes in traffic to AJAX endpoints associated with the YS LeadGen plugin.
* Deactivate the YS LeadGen plugin if an immediate upgrade is not feasible until the vulnerability is mitigated.
