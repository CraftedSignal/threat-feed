---
title: Suspicious DNS Queries to URL Shortening Services
slug: 2026-10-tinyurl-dns-queries
description: Threat actors frequently utilize URL shortening services like TinyURL to obfuscate malicious URLs used in phishing campaigns, malware staging, or command-and-control (C2) communication.
date: "2026-10-19T02:51:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - malware-loader
  - sysmon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: URL shorteners are frequently used by threat actors to obfuscate malicious destinations, including... command-and-control (C2) endpoints.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_dns_query_request_to_tinyurl.yml
  - https://x.com/Unit42_Intel/status/1919418143476199869
iocs:
  - type: domain
    value: tinyurl.com
ioc_counts:
  domain: 1
rules:
  - title: Detect Suspicious DNS Queries to TinyURL
    description: Detects potentially malicious processes or scripts performing DNS lookups to tinyurl.com, which is often used to obfuscate C2 or malware download URLs.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - dns_query
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Identify all non-browser processes initiating DNS queries to any known URL shortening domain.
      technique_id: T1105
      data_needed:
        - Sysmon Event ID 22
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: URL shorteners are frequently used by threat actors to obfuscate malicious destinations.
---

Threat actors commonly leverage URL shortening services, such as tinyurl.com, to hide the final destination of malicious payloads or command-and-control (C2) infrastructure from security appliances and defenders. By obfuscating the URL, attackers increase the difficulty of detecting phishing sites or malware distribution staging areas. While tinyurl.com is a legitimate service used for marketing and convenience, its interaction with non-browser processes - particularly script interpreters like PowerShell or command-line utilities executing from suspicious paths like AppData or Temp - is a high-fidelity indicator of potential malicious activity. This detection is designed to monitor for anomalous DNS resolution patterns that suggest a process is retrieving an obfuscated redirect, which is often a precursor to secondary stage downloads or C2 registration in malware families such as the Braodo Stealer.

## Impact

The use of obfuscated links via URL shorteners facilitates the delivery of various malware, including infostealers and loaders, to enterprise environments. Successful exploitation allows for the covert download of second-stage payloads, credential harvesting, and the establishment of persistent C2 channels. Organizations targeted by campaigns employing these techniques are at risk of data exfiltration and unauthorized system access.

## Recommendation

* Deploy the provided Sigma rule to identify non-browser processes initiating DNS queries to URL shorteners.
* Enable Sysmon Event ID 22 (DNS Query) across all endpoints to ensure visibility into DNS request patterns.
* Investigate the execution context of processes identified by the detection, focusing on the parent process and any subsequent outbound network connections.
* Tune the detection by adding process filters for legitimate business applications that may interface with URL shorteners via APIs, such as messaging clients or internal automation tools.
