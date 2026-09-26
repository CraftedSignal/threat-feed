---
title: Unauthenticated Remote Code Execution in Joomla UP Plugin
slug: 2026-09-joomla-up-plugin-rce
description: The Joomla UP plugin (Universal Plugin) is vulnerable to unauthenticated remote code execution via insecure GitHub action installation (CVE-2026-97163), allowing attackers to force the download of arbitrary code due to disabled TLS certificate verification.
date: "2026-09-26T21:45:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:lomart:up_plugin:*:*:*:*:*:joomla:*:*
tags:
  - web-application
  - rce
  - joomla
  - critical-vulnerability
vendors:
  - lomart
products:
  - UP (Universal Plugin) (5.0.0-5.2.0, 6.0.0-6.0.29)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The UP plugin contains an unauthenticated remote code execution vulnerability (CVE-2026-97163) allowing exploitation of public-facing Joomla installations.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An anonymous request can start an on-demand download of action code into plugins/content/up/actions/ where Joomla executes it.
    confidence_band: high
cves:
  - id: CVE-2026-97163
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97163
  - https://mysites.guru/blog/up-plugin-joomla-unauthenticated-vulnerabilities/
  - https://pocbit.org/pocs/cve-2026-97163
rules:
  - title: Detect CVE-2026-97163 Exploitation Attempt - UP Plugin Probe
    description: Detects unauthorized attempts to probe or trigger the UP plugin action installation mechanism via com_ajax or render parameters
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
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Joomla UP plugin to 5.2.1 or 6.1.0
      owner: IT Operations
      due: 24h
      evidence: Vendor release of 5.2.1/6.1.0 fixes
  hunt_leads:
    - lead: Search web logs for requests containing 'option=com_ajax' and 'plugin=up'
      technique_id: T1190
      data_needed:
        - Web access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PoC documentation suggests com_ajax patterns are used for installation
  mitigation_plan:
    - priority: immediate
      action: Enforce TLS and authorization constraints by upgrading plugin
      owner: IT Operations
      addresses: CVE-2026-97163
      evidence: Vulnerability remediated in version 6.1.0
---

The UP (Universal Plugin) for Joomla, developed by lomart.fr, contains a critical vulnerability (CVE-2026-97163) allowing unauthenticated remote code execution. The vulnerability exists in the plugin's "mini" package, which features an on-demand download mechanism for action code hosted on GitHub. During this process, the plugin fetches and unpacks remote ZIP archives into `plugins/content/up/actions/`, where the PHP code is subsequently executed by the Joomla framework.

Crucially, the plugin implementation fails to perform TLS certificate verification during these GitHub requests, and it lacks sufficient authorization controls for the installation trigger. This allows a network-positioned attacker (performing a Man-in-the-Middle attack) to intercept the request and inject a malicious archive. Exploitation results in the installation of arbitrary PHP code. The vulnerability impacts UP versions 5.0.0 through 5.2.0 and 6.0.0 through 6.0.29. Security patches have been released in versions 5.2.1 and 6.1.0, which enforce authorization and restore TLS verification.

## Attack Chain

1. Attacker performs reconnaissance to identify Joomla instances running the vulnerable UP plugin using indicators like `plugins/content/up/actions/` in HTTP traffic.
2. Attacker positions themselves as a Man-in-the-Middle between the target Joomla server and GitHub (e.g., via DNS spoofing or BGP hijacking).
3. Attacker triggers the plugin's on-demand action installation by sending an unauthenticated request to a component or endpoint that invokes the `up` plugin action loader.
4. The vulnerable plugin initiates a request to the attacker-controlled or spoofed GitHub URL to download an action pack.
5. Due to the lack of TLS certificate validation, the plugin accepts a malicious ZIP archive provided by the attacker.
6. The plugin automatically extracts the contents of the malicious archive into the `plugins/content/up/actions/` directory.
7. Attacker triggers the newly installed malicious PHP code by navigating to the corresponding plugin action path on the Joomla server.
8. Final objective is achieved: remote code execution under the privileges of the web server user.

## Impact

Successful exploitation results in full remote code execution on the underlying web server, potentially leading to total system compromise, data exfiltration, and lateral movement within the hosting infrastructure. The vulnerability is rated with a CVSS 4.0 score of 10.0, indicating the highest level of severity.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

- Patch Joomla UP plugin to version 5.2.1 or 6.1.0 immediately to enforce authorization and secure the fetch mechanism.
- Implement the Sigma rule provided below to detect anomalous web requests targeting the UP plugin's installation or rendering endpoints.
- Audit the `plugins/content/up/actions/` directory for any unexpected files or folders that were not part of the legitimate plugin deployment.
- Deploy network-layer inspection to identify unexpected outbound traffic from web servers targeting GitHub or unknown domains when initiated by the web application process.
