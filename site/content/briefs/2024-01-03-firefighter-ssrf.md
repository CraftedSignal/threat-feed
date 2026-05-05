---
title: FireFighter Unauthenticated SSRF Leads to Potential IAM Credential Theft
slug: 2024-01-03-firefighter-ssrf
description: FireFighter versions before 0.0.54 are vulnerable to an unauthenticated server-side request forgery (SSRF) vulnerability in the `/api/v2/firefighter/raid/jira_bot` endpoint, allowing attackers to potentially steal IAM credentials in cloud environments.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - cloud
  - iam
  - credential-theft
vendors:
  - Atlassian
products:
  - firefighter-incident (< 0.0.54)
  - Jira
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1133
    technique_name: External Remote Services
references:
  - https://github.com/advisories/GHSA-fqvv-jvhr-g5jc
iocs:
  - type: ip
    value: 169.254.169.254
ioc_counts:
  ip: 1
rules:
  - title: Detect Outbound Connection to Cloud Metadata Endpoint
    description: Detects connections from the FireFighter server to the cloud metadata endpoint, which could indicate SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect Unauthenticated POST to Jira Bot Endpoint
    description: Detects POST requests to the `/api/v2/firefighter/raid/jira_bot` endpoint without proper authentication headers, indicative of potential exploit attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FireFighter, a tool for incident management, contains a critical SSRF vulnerability affecting versions prior to 0.0.54. The vulnerability resides in the `CreateJiraBotView` endpoint (`/api/v2/firefighter/raid/jira_bot`), which lacks authentication and proper URL validation. An attacker can exploit this flaw to send arbitrary HTTP requests from the FireFighter server, including requests to internal cloud metadata endpoints. Specifically, in EC2/EKS environments without IMDSv2, this SSRF can be leveraged to steal temporary AWS credentials associated with the pod's IAM role. Successful exploitation allows an attacker to gain unauthorized access to cloud resources. The vulnerable code is located in `src/firefighter/raid/views/__init__.py`, `src/firefighter/raid/serializers.py`, and `src/firefighter/raid/client.py`.

## Attack Chain

1. An unauthenticated attacker sends a POST request to the `/api/v2/firefighter/raid/jira_bot` endpoint.
2. The attacker crafts a malicious request including an `attachments` parameter containing a URL pointing to a sensitive internal resource, such as the cloud metadata endpoint (`http://169.254.169.254/`).
3. The `LandbotIssueRequestSerializer.attachments` component processes the request without proper URL validation.
4. The `httpx.get()` function fetches the content from the attacker-specified URL.
5. The response from the metadata endpoint (containing AWS credentials) is retrieved by the FireFighter server.
6. The `RaidJiraClient.add_attachments_to_issue` function attaches the metadata response to a new Jira ticket.
7. The attacker retrieves the Jira ticket, extracting the attached file containing the stolen AWS credentials.
8. The attacker uses the stolen AWS credentials to gain unauthorized access to the compromised cloud environment.

## Impact

Successful exploitation of this SSRF vulnerability can lead to the theft of AWS IAM credentials in environments that do not enforce IMDSv2. This allows an attacker to gain unauthorized access to cloud resources, potentially leading to data breaches, service disruption, or other malicious activities. The number of affected deployments is currently unknown, but any FireFighter instance prior to version 0.0.54 is susceptible. Organizations using FireFighter for incident management are urged to upgrade immediately.

## Recommendation

*   Upgrade FireFighter to version 0.0.54 or later to patch the SSRF vulnerability.
*   Block access to the `/api/v2/firefighter/raid/jira_bot` endpoint from untrusted networks as a temporary workaround, as mentioned in the advisory.
*   Implement IMDSv2 with `HttpPutResponseHopLimit=1` on EC2/EKS nodes to mitigate the risk of IAM credential theft, as suggested in the advisory.
*   Monitor network connections originating from the FireFighter server, specifically looking for outbound connections to the cloud metadata endpoint (169.254.169.254) using network connection logs.
