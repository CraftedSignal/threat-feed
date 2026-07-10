---
title: Kubernetes Nginx Ingress LFI Attack
slug: 2024-01-09-kubernetes-nginx-lfi
description: Detection of local file inclusion (LFI) attacks targeting Kubernetes Nginx ingress controllers through analysis of Kubernetes logs.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - lfi
  - nginx
  - ingress
  - cloud
vendors:
  - Kubernetes
  - Nginx
products:
  - Nginx Ingress Controller
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Lateral Movement
    technique_id: T1212
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/splunk/splunk-connect-for-kubernetes
  - https://www.offensive-security.com/metasploit-unleashed/file-inclusion-vulnerabilities/
rules:
  - title: Kubernetes Nginx Ingress LFI Attempt
    description: Detects potential Local File Inclusion (LFI) attacks against Kubernetes Nginx Ingress Controllers by identifying suspicious file access patterns in request URLs.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1212
    data_sources:
      - webserver
      - linux
  - title: Kubernetes Nginx Ingress LFI - Status Code
    description: Detects LFI attempts resulting in specific status codes indicative of file access issues.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1212
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This brief focuses on detecting local file inclusion (LFI) attacks targeting Kubernetes Nginx ingress controllers. These attacks are identified by analyzing Kubernetes logs for suspicious patterns indicative of LFI attempts. The detection leverages Kubernetes logs, specifically parsing the `request` field to identify LFI patterns. Successful exploitation can lead to attackers reading sensitive files from the server, potentially exposing critical information. This activity is significant because it can lead to unauthorized access to sensitive data, further exploitation, and potential compromise of the Kubernetes environment. The provided detection logic originates from Splunk's security content and is designed to work with Kubernetes logs ingested via Splunk Connect for Kubernetes.

## Attack Chain

1.  Attacker identifies a Kubernetes Nginx ingress controller vulnerable to LFI.
2.  The attacker crafts a malicious HTTP request containing an LFI payload within the URL. This payload aims to access sensitive files on the server.
3.  The crafted request is sent to the Kubernetes Nginx ingress controller.
4.  The Nginx ingress controller processes the request and attempts to access the file specified in the malicious payload.
5.  If the LFI vulnerability is successfully exploited, the targeted file's contents are exposed to the attacker.
6.  The attacker retrieves the contents of the sensitive file from the HTTP response.
7.  The attacker analyzes the exfiltrated file contents for sensitive information, such as credentials or configuration details.

## Impact

A successful LFI attack against a Kubernetes Nginx ingress controller can lead to the exposure of sensitive data, potentially including configuration files, credentials, or internal application code. This can lead to further exploitation, such as privilege escalation or lateral movement within the Kubernetes cluster. The number of affected systems and organizations depends on the scope of the vulnerable ingress controllers.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect LFI attempts against Kubernetes Nginx ingress controllers based on suspicious URL patterns and log data.
*   Ensure that Kubernetes logs are being ingested through Splunk Connect for Kubernetes, as this is a prerequisite for the detection logic.
*   Investigate and remediate any identified LFI vulnerabilities in Kubernetes Nginx ingress controllers to prevent successful exploitation.
*   Use the provided drilldown searches to pivot into detection results based on host and risk events.
