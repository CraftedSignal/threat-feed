---
title: 'CVE-2026-8848: Popup Maker WordPress Plugin Authorization Bypass Leading to RCE'
slug: 2026-07-popup-maker-auth-bypass
description: An authorization bypass vulnerability, CVE-2026-8848, exists in the Popup Maker WordPress plugin versions up to and including 1.22.0, allowing authenticated attackers with editor-level access or higher to install and activate arbitrary plugins from a controlled URL, which leads to remote code execution, provided a valid Popup Maker Pro license is active and the Pro version is not yet installed.
date: "2026-07-09T08:24:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - web-exploitation
  - vulnerability
  - rce
  - authorization-bypass
vendors:
  - Popup Maker
products:
  - Popup Maker – Boost Sales, Conversions, Optins, Subscribers with the Ultimate WP Popup Builder plugin <= 1.22.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for authenticated attackers... to install and activate an arbitrary plugin from an attacker-controlled URL, leading to remote code execution.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: authorization bypass... allows authenticated attackers, with editor-level access and above, to install and activate an arbitrary plugin from an attacker-controlled URL, leading to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-8848
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8848
rules:
  - title: Detect CVE-2026-8848 Exploitation Attempt - Popup Maker Legacy Endpoint Access
    description: Detects HTTP requests to the Popup Maker plugin's legacy v1/connect/info endpoint, which is a necessary step for CVE-2026-8848 exploitation leading to RCE.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical authorization bypass vulnerability, identified as CVE-2026-8848, has been discovered in all versions up to and including 1.22.0 of the "Popup Maker - Boost Sales, Conversions, Optins, Subscribers with the Ultimate WP Popup Builder" plugin for WordPress. This flaw enables authenticated attackers possessing editor-level access or higher to circumvent proper authorization checks. The vulnerability allows these attackers to install and activate any arbitrary plugin from an attacker-controlled URL, ultimately leading to remote code execution (RCE) on the compromised WordPress instance. Successful exploitation hinges on two specific pre-conditions: an active Popup Maker Pro license must be present on the target site, and the Popup Maker Pro version must not yet be installed. These conditions are crucial as they allow a legacy `v1/connect/info` endpoint to issue a bearer token, which in turn satisfies a validation check required by the plugin's install endpoint.

## Attack Chain

1. **Initial Access**: An authenticated attacker, possessing editor-level or higher privileges, gains access to the WordPress administration interface of a site running the vulnerable Popup Maker plugin (version 1.22.0 or earlier).
2. **Pre-Condition Fulfillment**: The attacker confirms that the target WordPress site has an active Popup Maker Pro license and that the Popup Maker Pro version of the plugin is not currently installed.
3. **Bearer Token Acquisition**: The attacker sends a crafted request to the plugin's legacy `v1/connect/info` endpoint (e.g., `/wp-content/plugins/popup-maker/v1/connect/info`). Under the specific conditions met in the previous step, this endpoint improperly issues a valid bearer token.
4. **Authorization Bypass**: The attacker utilizes the acquired bearer token to bypass the authorization and validation checks on a Popup Maker plugin installation endpoint, which would normally prevent editor-level users from installing plugins.
5. **Malicious Plugin Provisioning**: The attacker specifies a URL pointing to a malicious WordPress plugin hosted on an attacker-controlled server.
6. **Arbitrary Plugin Installation and Activation**: The vulnerable Popup Maker functionality processes the request, downloads, installs, and activates the arbitrary malicious plugin from the attacker-provided URL.
7. **Impact**: Upon activation, the malicious plugin executes code with the privileges of the web server, resulting in remote code execution (RCE) on the underlying operating system of the WordPress host.

## Impact

The successful exploitation of CVE-2026-8848 allows an attacker to achieve remote code execution on the WordPress host server. This can lead to complete compromise of the website and server, including defacement, data theft, insertion of backdoors, further lateral movement within the network, and establishment of persistent access. While requiring editor-level authentication, the ability to escalate privileges to RCE poses a severe risk to the integrity and confidentiality of the affected systems and data.

## Recommendation

* Immediately update the "Popup Maker - Boost Sales, Conversions, Optins, Subscribers with the Ultimate WP Popup Builder" plugin to version 1.22.1 or higher to patch CVE-2026-8848.
* Deploy the provided Sigma rule to detect anomalous access patterns to the legacy `v1/connect/info` endpoint, which is a key step in the exploitation chain for CVE-2026-8848.
* Ensure `webserver` access logs are enabled and configured to capture full URI paths (`cs-uri-stem` and `cs-uri-query`) and HTTP methods for improved visibility.
