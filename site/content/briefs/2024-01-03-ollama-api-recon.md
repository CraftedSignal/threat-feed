---
title: Ollama API Endpoint Scan Reconnaissance
slug: 2024-01-03-ollama-api-recon
description: Detects potential reconnaissance activity against Ollama servers by identifying sources probing multiple API endpoints within short timeframes, indicative of attackers mapping the API surface for vulnerabilities.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ollama
  - api-reconnaissance
  - web-application
vendors:
  - Ollama
products:
  - Ollama
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Reconnaissance
    technique_id: T1595
    technique_name: Active Scanning
references:
  - https://github.com/rosplk/ta-ollama
rules:
  - title: Ollama Server GIN Log Pattern
    description: Detects the presence of '[GIN]' in Ollama server logs, potentially indicating server activity and serving as a baseline indicator for further analysis.
    platform: sigma
    severity: informational
    tactics:
      - resource_development
    techniques:
      - T1588
    data_sources:
      - webserver
      - linux
rules_count: 1
---

This detection focuses on identifying reconnaissance attempts against Ollama servers. The core objective is to pinpoint sources that aggressively probe multiple API endpoints within short time windows. This behavior often signifies a systematic effort to enumerate the API surface, uncover hidden endpoints, or pinpoint potential vulnerabilities before launching targeted attacks. The detection leverages Ollama server logs to track API access patterns. It is crucial for defenders to identify and mitigate such reconnaissance attempts proactively to prevent potential exploitation of Ollama servers. This detection is based on data from the Splunk ES-CU detections, specifically `detections/application/ollama_possible_api_endpoint_scan_reconnaissance.yml`.

## Attack Chain

1.  Attacker gains network access to an Ollama server.
2.  Attacker initiates a series of HTTP requests targeting various API endpoints on the Ollama server.
3.  The attacker uses a variety of HTTP methods (e.g., HEAD, GET) to probe the endpoints.
4.  The attacker analyzes the HTTP response codes to map the API surface and identify active endpoints.
5.  The attacker identifies potential vulnerabilities based on endpoint behavior and response patterns.
6.  The attacker attempts to exploit identified vulnerabilities.
7.  If successful, the attacker gains unauthorized access to Ollama server resources.
8.  The attacker exfiltrates sensitive data or disrupts Ollama services.

## Impact

Successful API reconnaissance can lead to the discovery of vulnerabilities in Ollama servers, enabling attackers to gain unauthorized access, exfiltrate sensitive data, or disrupt services. While the number of potential victims isn't explicitly stated, organizations using Ollama servers are at risk. The detection focuses on identifying the reconnaissance phase, allowing defenders to interrupt the attack chain before significant damage occurs.

## Recommendation

*   Deploy the following Sigma rule to detect potential Ollama API reconnaissance activity based on excessive requests (`total_requests > 120`) within a 5-minute window.
*   Ingest Ollama logs via Splunk TA-ollama add-on by configuring file monitoring inputs pointed to your Ollama server log directories to enable effective detection.
*   Investigate any alerts triggered by the Sigma rule, focusing on the source IP address (`src`) and the accessed endpoints (`dest`) to determine the legitimacy of the activity.
