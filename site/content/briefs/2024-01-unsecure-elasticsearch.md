---
title: Unsecured Elasticsearch Node Inbound Connection
slug: 2024-01-unsecure-elasticsearch
description: This rule identifies potentially unsecured Elasticsearch nodes that lack TLS and/or authentication and are accepting inbound network connections, which could allow adversaries to gain initial access, exfiltrate data, or disrupt services.
date: "2024-01-03T14:25:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - elasticsearch
  - initial-access
  - reconnaissance
  - network
vendors:
  - Elastic
products:
  - Elasticsearch
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1595
    technique_name: Active Scanning
references:
  - https://www.elastic.co/guide/en/elasticsearch/reference/current/configuring-security.html
  - https://www.elastic.co/guide/en/beats/packetbeat/current/packetbeat-http-options.html#_send_all_headers
rules:
  - title: Inbound Connection to Unsecured Elasticsearch Node
    description: Detects inbound connections to Elasticsearch nodes on port 9200 without authentication headers.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - reconnaissance
    techniques:
      - T1190
      - T1595
    data_sources:
      - network_connection
      - windows
  - title: Elasticsearch Node Without Authentication Header
    description: Detects network traffic to Elasticsearch nodes lacking an authorization header.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - reconnaissance
    techniques:
      - T1190
      - T1595
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This detection rule identifies Elasticsearch nodes that do not have Transport Layer Security (TLS) enabled, lack authentication mechanisms, and are accepting inbound network connections over the default Elasticsearch port (9200). Elasticsearch is a search and analytics engine, and misconfigured instances can be vulnerable to unauthorized access. This rule aims to detect initial access attempts by identifying connections lacking authentication headers, which indicates a potential exploitation attempt. The rule is triggered by inbound HTTP traffic on port 9200 without authorization headers. The rule leverages network traffic data to identify insecure configurations.

## Attack Chain

1.  An attacker scans the network for exposed Elasticsearch nodes on port 9200.
2.  The attacker identifies an Elasticsearch node that lacks TLS and authentication.
3.  The attacker establishes an inbound HTTP connection to the exposed Elasticsearch node on port 9200.
4.  The HTTP request from the attacker does not contain an authorization header.
5.  The Elasticsearch node responds with a 200 OK status code, indicating a successful connection.
6.  The attacker sends requests to access sensitive data or manipulate the Elasticsearch cluster.
7.  The attacker exfiltrates data or disrupts services due to the lack of security controls.

## Impact

Successful exploitation of unsecured Elasticsearch nodes can lead to significant data breaches, service disruption, and reputational damage. An attacker can gain unauthorized access to sensitive data stored in the Elasticsearch cluster, leading to data exfiltration or manipulation. Depending on the data stored, this could expose personally identifiable information (PII), financial data, or other confidential information. Service disruption can occur due to unauthorized modifications or deletion of indices.

## Recommendation

*   Enable Sysmon network connection logging to activate the rules below.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Ensure that the `HTTP` protocol configuration in `packetbeat.yml` includes port `9200` and `send_all_headers` as documented in the references.
*   Implement Transport Layer Security (TLS) and enable authentication mechanisms on all Elasticsearch nodes, referencing the Elasticsearch security configuration guide.
