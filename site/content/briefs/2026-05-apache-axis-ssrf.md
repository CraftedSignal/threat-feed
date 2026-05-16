---
title: Apache Axis 1.4 Server-Side Request Forgery Vulnerability (CVE-2019-0227) Exploit
slug: 2026-05-apache-axis-ssrf
description: A public exploit has been released for CVE-2019-0227, a Server-Side Request Forgery vulnerability in Apache Axis 1.4 and earlier, allowing unauthenticated remote command execution when `enableRemoteAdmin` is true via deployment of a malicious webservice and webshell.
date: "2026-05-16T13:01:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:apache:axis:1.4:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:agile_engineering_data_management:6.2.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:agile_product_lifecycle_management:9.3.3:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:application_testing_suite:13.2.0.1:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:application_testing_suite:13.3.0.1:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:big_data_discovery:1.6:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_asap_cartridges:7.2:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_asap_cartridges:7.3:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_design_studio:7.3.4.3.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_design_studio:7.3.5.5.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_design_studio:7.4.0.4.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_design_studio:7.4.1.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_element_manager:8.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_element_manager:8.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_element_manager:8.1.1:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_element_manager:8.2.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_network_integrity:7.3.5:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_network_integrity:7.3.6:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_order_and_service_management:7.3.0.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_order_and_service_management:7.4:*:*:*:*:*:*:*
tags:
  - ssrf
  - rce
  - apache
vendors:
  - Apache
products:
  - Axis
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2019-0227
    cvss: 7.5
    epss: 0.89877
references:
  - https://sploitus.com/exploit?id=371B14AC-8018-52E8-89C5-302C7B59C44F&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=371B14AC-8018-52E8-89C5-302C7B59C44F
iocs:
  - type: url
    value: http://target.com:8080/axis/
ioc_counts:
  url: 1
rules:
  - title: Detect CVE-2019-0227 Exploitation Attempt via AdminService
    description: Detects CVE-2019-0227 exploitation attempt — POST request to AdminService to deploy malicious service
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
  - title: Detect Webshell Creation via Axis LogHandler
    description: Detects webshell creation via Axis LogHandler by monitoring for file writes to common webshell locations with JSP extensions
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A public exploit has been published detailing a Server-Side Request Forgery (SSRF) vulnerability in Apache Axis version 1.4 and earlier, tracked as CVE-2019-0227. The vulnerability can lead to remote command execution (RCE) if the `enableRemoteAdmin` attribute is set to `true`. An attacker can leverage the `AdminService` interface to deploy a malicious WebService and use a `LogHandler` to write a Webshell. The availability of a working exploit, particularly the `axis_exp.py` Python script, significantly increases the risk to unpatched Apache Axis installations with the `enableRemoteAdmin` setting enabled. This script automates the deployment of malicious services and facilitates interactive command execution on the compromised server.

## Attack Chain

1.  The attacker sends a POST request to `/axis/services/AdminService` to deploy a malicious service.
2.  The deployed service creates a `RandomService` that triggers a `RandomLog` on each request.
3.  The `RandomLog` handler is configured to write a JSP webshell (e.g., `shell.jsp`) to the web application's root directory (e.g., `../webapps/ROOT/shell.jsp`).
4.  The attacker sends a POST request to `/axis/services/RandomService` to trigger the `RandomLog` handler and write the JSP webshell.
5.  The webshell writes JSP code from the request into the `shell.jsp` file.
6.  The attacker sends a GET request to `/shell.jsp?c=command`, where `command` is the system command to execute.
7.  The server executes the command passed in the `c` parameter and returns the result.
8.  The attacker gains arbitrary code execution on the target system.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary system commands on the target server. This can lead to complete system compromise, data theft, and deployment of further malicious payloads. The exploit tool automates webshell deployment, lowering the barrier to entry for attackers. Exposed Apache Axis installations are vulnerable if the `enableRemoteAdmin` setting is enabled, and if exploited can result in significant data breaches.

## Recommendation

*   Disable the `enableRemoteAdmin` attribute in the Apache Axis configuration to prevent remote administration as detailed in the advisory.
*   Monitor webserver logs for POST requests to `/axis/services/AdminService` as a potential indicator of exploit attempts (see the rule "Detect CVE-2019-0227 Exploitation Attempt via AdminService").
*   Implement access controls to restrict access to the `/services/AdminService` endpoint.
*   Deploy the Sigma rule "Detect Webshell Creation via Axis LogHandler" to identify webshell creation attempts via the LogHandler.
*   Monitor webserver logs for GET requests to JSP files in the web application's root directory with a 'c' parameter for command execution as indicators of compromise.
*   Upgrade to a supported and patched version of Apache Axis or migrate to another web service framework.
