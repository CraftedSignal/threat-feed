---
title: Argument Injection in LibreNMS graph_title Parameter
slug: 2026-09-librenms-argument-injection
description: Authenticated attackers can exploit CVE-2026-86427 in LibreNMS before version 26.8.0 to inject arbitrary rrdtool arguments, bypassing authorization controls to read unauthorized RRD files or execute commands.
date: "2026-09-07T13:36:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:librenms:librenms:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - command-injection
vendors:
  - LibreNMS
products:
  - LibreNMS (< 26.8.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can use newline injection to execute arbitrary rrdtool commands, bypassing per-device authorization checks.
    confidence_band: high
cves:
  - id: CVE-2026-86427
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86427
rules:
  - title: Detect CVE-2026-86427 Exploitation Attempt - graph_title Argument Injection
    description: Detects HTTP requests containing potential argument injection patterns in the graph_title parameter, such as newlines or rrdtool flag injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade LibreNMS to 26.8.0
      owner: IT Operations
      due: 24h
      evidence: Source document indicates LibreNMS before 26.8.0 contains the vulnerability
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to sanitize graph_title parameter input
      owner: IT Operations
      addresses: CVE-2026-86427
      evidence: Vulnerability exists in parameter handling
---

LibreNMS versions prior to 26.8.0 are susceptible to an argument injection vulnerability identified as CVE-2026-86427. The vulnerability exists within the processing of the 'graph_title' parameter, where insufficient neutralization of special characters allows an authenticated attacker to break out of the intended double-quote escaping. By manipulating this parameter, an attacker can influence the execution of the 'rrdtool' utility. This allows for the injection of malicious 'DEF' and 'LINE' arguments, facilitating the unauthorized retrieval of RRD database files belonging to other monitored devices. Furthermore, the use of newline injection enables the execution of arbitrary 'rrdtool' commands, allowing attackers to bypass configured per-device authorization checks. This flaw poses a significant risk to the integrity and confidentiality of network monitoring data managed by LibreNMS.

## Impact

Successful exploitation allows authenticated users to access sensitive network performance data from unauthorized devices or execute arbitrary commands within the context of the rrdtool process. This can lead to unauthorized information disclosure and potential escalation of control over the monitoring platform.

## Recommendation

* Upgrade LibreNMS instances to version 26.8.0 or later immediately to patch the argument injection vulnerability in the graph_title parameter.
* Review web server access logs for requests containing newline characters or suspicious rrdtool flags (e.g., DEF, LINE) within the graph_title parameter string.
* Restrict access to the LibreNMS monitoring interface to trusted users only to mitigate the risk from authenticated attackers.
