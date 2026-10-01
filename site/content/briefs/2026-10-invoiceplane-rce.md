---
title: Remote Code Execution in InvoicePlane via Configuration Injection
slug: 2026-10-invoiceplane-rce
description: InvoicePlane 1.7.1 is vulnerable to remote code execution (CVE-2026-40297) due to unsanitized input in the setup module, allowing attackers to inject arbitrary configuration directives.
date: "2026-10-01T15:13:02Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - InvoicePlane
products:
  - InvoicePlane (1.7.1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A critical configuration injection vulnerability exists in the application’s setup module.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This can lead to environment manipulation, debug mode activation, and potential remote code execution depending on deployment context.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52685
  - https://github.com/InvoicePlane/InvoicePlane
  - https://github.com/InvoicePlane/InvoicePlane/security/advisories/GHSA-ffq5-mw9f-mv6j
rules:
  - title: Detect CVE-2026-40297 Exploitation - Configuration Injection in InvoicePlane
    description: Detects exploitation attempts against CVE-2026-40297 by identifying malicious newline character injection in the db_hostname parameter during the setup database configuration step.
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade InvoicePlane to 1.7.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly states patched in 1.7.2.
  hunt_leads:
    - lead: Unauthorized POST requests to setup configuration endpoint.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit requires interaction with setup endpoint.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /setup/ directory via WAF or web server configuration.
      owner: IT Operations
      addresses: CVE-2026-40297
      evidence: Vulnerability exists in the setup module.
---

InvoicePlane version 1.7.1 contains a critical configuration injection vulnerability (CVE-2026-40297) located within the application's setup module. The vulnerability stems from improper input validation of the 'db_hostname' parameter during the initial installation flow. An unauthenticated attacker can supply malicious input to this parameter to inject arbitrary configuration values into the application's runtime environment. This can be leveraged to activate debug modes, manipulate environment variables, and ultimately achieve remote code execution depending on the server deployment context. This vulnerability was disclosed alongside a proof-of-concept that demonstrates the sequential exploitation of CSRF-protected steps to facilitate the configuration injection.

## Attack Chain

1. Attacker initiates the InvoicePlane setup process by accessing the /index.php/setup/language endpoint.
2. Attacker scrapes the first CSRF token (_ip_csrf) from the language selection page.
3. Attacker submits the language step via POST to confirm the configuration flow progress.
4. Attacker navigates to the /index.php/setup/prerequisites endpoint to retrieve the secondary CSRF token.
5. Attacker submits the prerequisites step via POST to advance the installer.
6. Attacker navigates to the /index.php/setup/configure_database endpoint and retrieves the final CSRF token.
7. Attacker submits a POST request to configure_database containing a crafted db_hostname payload that escapes the expected string and injects new configuration lines (e.g., ENABLE_DEBUG=true).
8. Application parses the injected configuration, resulting in environment manipulation and potential remote code execution.

## Impact

Successful exploitation allows an attacker to inject arbitrary configuration, modify application behavior, and potentially execute code with the permissions of the web server user. This vulnerability exposes the application to full compromise during the setup phase, affecting any deployment running version 1.7.1.

## Recommendation

Prioritized actions for security teams:
- Patch immediately by upgrading InvoicePlane to version 1.7.2 or later.
- Implement strict network access controls to the /setup/ directory to prevent unauthenticated access to the installation module.
- Audit web application access logs for repeated POST requests to '/index.php/setup/configure_database' originating from unauthorized IP addresses.
- Deploy web application firewall (WAF) rules to detect and block requests to '/index.php/setup/configure_database' containing injected configuration directives (e.g., ENABLE_DEBUG, newline characters followed by configuration keys) within the 'db_hostname' parameter.
