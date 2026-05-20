---
title: Taiko AG1000-01A SMS Alert Gateway Stored XSS (CVE-2026-9144)
slug: 2026-05-taiko-xss
description: Taiko AG1000-01A SMS Alert Gateway Rev 7.3 and Rev 8 is vulnerable to stored cross-site scripting (CVE-2026-9144) in the web configuration interface, allowing authenticated attackers to execute persistent JavaScript by fragmenting malicious payloads across multiple administrative form fields for persistent code execution.
date: "2026-05-20T20:19:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - stored_xss
  - CVE-2026-9144
  - web_application
vendors:
  - Taiko
products:
  - AG1000-01A SMS Alert Gateway
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-9144
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9144
rules:
  - title: Detect Taiko AG1000-01A Fragmented XSS Attempt
    description: Detects CVE-2026-9144 exploitation — attempts to inject malicious JavaScript by fragmenting payloads across multiple administrative form fields
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1059.007
    data_sources:
      - webserver
  - title: Detect Taiko AG1000-01A Stored XSS via Admin Forms
    description: Detects CVE-2026-9144 exploitation — stored XSS attempts through administrative forms by searching for common XSS vectors in POST requests
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 2
---

The Taiko AG1000-01A SMS Alert Gateway Rev 7.3 and Rev 8 contains a stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-9144, within its embedded web configuration interface. This flaw enables authenticated attackers to inject and execute persistent JavaScript code within the administrative dashboard. The attack involves bypassing front-end length restrictions by fragmenting malicious payloads across multiple administrative form fields, using techniques like JavaScript comments and template literals to concatenate executable script fragments. These fragments are then rendered in administrative dashboard views, such as index.zhtml, leading to persistent script execution whenever an administrator accesses the affected pages. This vulnerability poses a significant risk to the confidentiality and integrity of the SMS Alert Gateway.

## Attack Chain

1. An attacker authenticates to the Taiko AG1000-01A SMS Alert Gateway web configuration interface.
2. The attacker identifies multiple administrative form fields that allow input.
3. The attacker crafts a malicious JavaScript payload, designed to execute arbitrary commands or exfiltrate sensitive data.
4. The attacker fragments the payload into smaller chunks, using JavaScript comments (`/* ... */`) and template literals to bypass front-end length restrictions on the form fields.
5. The attacker submits the fragmented payload across multiple administrative form fields.
6. When an administrator accesses a dashboard view such as `index.zhtml`, the fragmented JavaScript payload is reassembled and executed within the administrator's browser.
7. The executed JavaScript can perform actions such as stealing administrator cookies, modifying configuration settings, or launching further attacks against the gateway.
8. The attacker achieves persistent code execution on the SMS Alert Gateway administrative interface, potentially compromising the entire system.

## Impact

Successful exploitation of this stored XSS vulnerability (CVE-2026-9144) could allow an attacker to compromise the Taiko AG1000-01A SMS Alert Gateway. The attacker could gain unauthorized access to sensitive configuration data, modify alert settings, or even use the gateway as a platform for launching further attacks. Given the nature of SMS alert gateways, a compromised device could be used to send malicious SMS messages, leading to potential phishing or malware distribution campaigns.

## Recommendation

*   Deploy the Sigma rule `Detect Taiko AG1000-01A Fragmented XSS Attempt` to detect attempts to inject malicious JavaScript by fragmenting payloads across multiple administrative form fields in web server logs.
*   Apply input validation and output encoding to all administrative form fields on the Taiko AG1000-01A SMS Alert Gateway to prevent XSS attacks.
*   Monitor web server logs for suspicious activity related to the web configuration interface, focusing on requests with fragmented JavaScript payloads.
*   Apply any available patches or updates from Taiko to address CVE-2026-9144.
