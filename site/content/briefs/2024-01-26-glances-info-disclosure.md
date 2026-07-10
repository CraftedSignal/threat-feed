---
title: Glances Cross-Origin Information Disclosure via Unauthenticated REST API
slug: 2024-01-26-glances-info-disclosure
description: Glances versions before 4.5.4 are vulnerable to cross-origin information disclosure, where a malicious website can retrieve sensitive system information from a running Glances instance due to a permissive CORS policy on the `/api/4/all` endpoint.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - glances
  - information-disclosure
  - cors
  - webserver
vendors:
  - Glances
products:
  - Glances
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2026-34839
references:
  - https://github.com/advisories/GHSA-gfc2-9qmw-w7vh
rules:
  - title: Detect Glances Web Mode Startup
    description: Detects Glances being started in web mode, which is a prerequisite for exploiting the CORS vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Glances API Access from Browser Process
    description: Detects network connections to the Glances API port (61208) from browser processes, potentially indicating exploitation.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595.002
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Glances, a system monitoring tool, exposes a REST API (`/api/4/*`) that is accessible without authentication. Prior to version 4.5.4, a permissive Cross-Origin Resource Sharing (CORS) policy (`Access-Control-Allow-Origin: *`) allows cross-origin requests from any website. An attacker can exploit this vulnerability by hosting a malicious website that, when visited by a user running Glances in web mode (e.g., `glances -w -B 0.0.0.0`), can retrieve sensitive system information via the user's browser. This information includes process lists, system details (hostname, OS, CPU info), memory and disk usage, network interfaces and IP addresses, and running services and metrics. The vulnerability, identified as CVE-2026-34839, allows for unauthenticated remote information disclosure.

## Attack Chain

1.  A victim starts Glances in web mode using the command `glances -w -B 0.0.0.0`, exposing the REST API on port 61208.
2.  The victim visits a malicious website controlled by the attacker.
3.  The malicious website contains JavaScript code that sends an HTTP GET request to the Glances API endpoint `http://<victim-ip>:61208/api/4/all`.
4.  Due to the permissive CORS policy (`Access-Control-Allow-Origin: *`), the Glances server allows the cross-origin request.
5.  The Glances server responds with a JSON payload containing sensitive system information, including process lists, system details, network configuration, and resource usage.
6.  The malicious JavaScript code parses the JSON response and extracts the sensitive information.
7.  The extracted information is logged to the attacker's console or sent to an attacker-controlled server for analysis and further exploitation.
8.  The attacker uses the disclosed information for reconnaissance, identifying potential targets for further attacks.

## Impact

Successful exploitation of this vulnerability allows a remote, unauthenticated attacker to gather sensitive information about the victim's system. This can lead to a comprehensive system fingerprint, including running processes, network configuration, and internal IP addresses. While the exact number of victims is unknown, any Glances instance running in web mode with a vulnerable version (prior to 4.5.4) is susceptible. This information disclosure can be used for targeted attacks, such as exploiting other vulnerabilities based on the identified software and configurations or performing social engineering attacks based on the disclosed system information.

## Recommendation

*   Upgrade Glances to version 4.5.4 or later to patch CVE-2026-34839.
*   Implement network monitoring rules to detect unusual outbound connections from browsers to port 61208, indicating potential exploitation attempts. See the "Detect Glances API Access from Browser Process" Sigma rule below.
*   Deploy the Sigma rule "Detect Glances Web Mode Startup" to identify instances of Glances being run in web mode.
*   Review and restrict network exposure of Glances web interface by modifying the `-B` parameter, avoiding `0.0.0.0`, to limit the scope of the exposed API.
