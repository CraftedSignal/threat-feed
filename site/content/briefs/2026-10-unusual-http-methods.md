---
title: Detection of Unusual HTTP Request Methods for Protocol Abuse
slug: 2026-10-unusual-http-methods
description: This analytic identifies potential exploitation, command-and-control communication, or protocol abuse by monitoring Zeek logs for HTTP requests using non-standard or unexpected methods.
date: "2026-10-13T17:41:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - protocol-abuse
  - c2
  - web-exploitation
  - network-monitoring
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Unusual methods can indicate protocol abuse, exploitation attempts, or command-and-control traffic.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unusual methods can indicate protocol abuse, exploitation attempts, or command-and-control traffic.
    confidence_band: med
rules:
  - title: Detect Unusual HTTP Request Methods
    description: Detects HTTP requests using methods outside the standard allowlist, which may indicate exploitation attempts or custom C2 communication.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - initial_access
    techniques:
      - T1071.001
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Review current Zeek logs for methods not present in the allowlist
      owner: SOC
      due: 48h
      evidence: Source documentation for unusual HTTP method detection
  hunt_leads:
    - lead: Search for HTTP methods that are not standard HTTP/1.1 or HTTP/2 methods
      technique_id: T1071.001
      data_needed:
        - Zeek HTTP logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Unusual HTTP request methods as identified in source
---

This detection focuses on identifying anomalous HTTP traffic by surfacing request methods that fall outside a defined allowlist of standard operations. By monitoring Zeek HTTP logs, defenders can uncover attempts at protocol abuse, such as HTTP request smuggling, or the usage of custom, non-standard methods characteristic of proprietary command-and-control (C2) protocols. 

The scope includes any network environment utilizing Zeek for traffic analysis. Because legitimate applications and internal frameworks occasionally use non-standard HTTP methods, this detection is intended to be tuned by establishing a baseline of expected traffic and adding confirmed business-critical methods to the ignore list. It provides essential visibility into potential initial access attempts exploiting web server vulnerabilities or persistent C2 beaconing.

## Impact

Successful attacks leveraging unusual HTTP methods can result in unauthenticated remote code execution, unauthorized data exfiltration, or persistence through covert C2 channels. The detection of these methods enables early identification of adversary infrastructure, potentially preventing compromise across enterprise web server environments.

## Recommendation

- Deploy the provided Sigma rule to your SIEM to monitor for non-standard HTTP methods observed in Zeek logs.
- Review the method, source, destination, and URI for all detected anomalies to distinguish between malicious protocol abuse and legitimate internal application traffic.
- Baseline your organization's environment to identify legitimate non-standard HTTP methods used by internal frameworks and update the rule allowlist to minimize false positives.
- Integrate Zeek HTTP logs into your SIEM using the official Splunk Add-on for Zeek to ensure the `zeek_http` data source is correctly populated.
