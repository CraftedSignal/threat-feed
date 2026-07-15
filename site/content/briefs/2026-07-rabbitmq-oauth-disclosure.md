---
title: RabbitMQ Unauthenticated OAuth Client Credential Disclosure via HTTP API (CVE-2026-57219)
slug: 2026-07-rabbitmq-oauth-disclosure
description: CVE-2026-57219 describes an unauthenticated disclosure vulnerability in RabbitMQ, allowing an attacker to obtain OAuth client credentials via an HTTP API endpoint when RabbitMQ is configured with certain less common OAuth 2 configurations, potentially leading to unauthorized access to other systems or services.
date: "2026-07-15T07:42:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:broadcom:rabbitmq_server:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - credential-access
  - rabbitmq
  - broadcom
vendors:
  - Broadcom
products:
  - RabbitMQ
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: unauthenticated disclosure of OAuth client credentials via an HTTP API endpoint
    confidence_band: high
cves:
  - id: CVE-2026-57219
    cvss: 7.5
    epss: 0.00359
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57219
---

CVE-2026-57219 identifies a critical vulnerability in RabbitMQ, specifically affecting instances configured with certain less common OAuth 2 configurations. This flaw allows an unauthenticated attacker to obtain sensitive OAuth client credentials directly via an HTTP API endpoint. The vulnerability stems from an improper handling mechanism when these specific OAuth 2 configurations are in use, leading to the unintended disclosure of client secrets and other credential information. While the exact "less common" configurations are not detailed, their presence creates a window for attackers to gain unauthorized access to any services or applications that rely on these compromised OAuth clients for authentication. This vulnerability could lead to significant security breaches, including data exfiltration, privilege escalation, and lateral movement within an affected organization's network, as the stolen credentials can be leveraged to impersonate legitimate services or users.

## Attack Chain

1. **Reconnaissance & Configuration Identification**: An attacker identifies an internet-facing RabbitMQ instance within a target organization and attempts to determine if it is utilizing the "less common OAuth 2 configurations" described in CVE-2026-57219.
2. **Vulnerability Exploitation**: The attacker sends a specially crafted, unauthenticated HTTP request to a specific vulnerable HTTP API endpoint exposed by the RabbitMQ server.
3. **Credential Disclosure**: Due to the flaw described in CVE-2026-57219, the RabbitMQ instance responds to this unauthenticated request by inadvertently disclosing sensitive OAuth client credentials, such as client IDs and client secrets.
4. **Credential Exfiltration**: The attacker parses the HTTP response and extracts the disclosed OAuth client credentials, often through automated tools.
5. **Unauthorized Authentication**: The attacker then uses the stolen OAuth client credentials to authenticate to other services or applications that trust the compromised RabbitMQ instance or utilize these specific OAuth clients for identity management.
6. **Lateral Movement & Access**: Successful authentication grants the attacker unauthorized access to internal systems, data repositories, or other resources that are accessible via the stolen credentials, facilitating lateral movement within the network.
7. **Impact Fulfillment**: The attacker leverages this unauthorized access to achieve their objectives, which could include data exfiltration, privilege escalation, or further system compromise.

## Impact

Successful exploitation of CVE-2026-57219 can lead to severe consequences for organizations using affected RabbitMQ configurations. The primary impact is the unauthorized disclosure of OAuth client credentials, which can then be used to gain unauthorized access to various systems and data within the victim's environment. This could result in widespread data breaches, financial losses, and significant reputational damage. The unauthorized access may extend to sensitive internal systems, cloud services, or applications that rely on RabbitMQ's OAuth integration, potentially compromising customer data, intellectual property, and critical infrastructure. No specific victim counts or targeted sectors have been publicly identified at this time, but any organization using vulnerable RabbitMQ configurations is at risk.

## Recommendation

* Immediately patch RabbitMQ instances to a version that addresses CVE-2026-57219 to prevent unauthenticated credential disclosure.
* Review all existing RabbitMQ OAuth 2 configurations to identify and remediate any "less common" or non-standard setups that could be susceptible to CVE-2026-57219.
* Monitor RabbitMQ HTTP access logs and associated authentication logs for unusual or unauthenticated access attempts to API endpoints that handle OAuth configurations.
* Implement robust monitoring of all services that utilize OAuth clients managed by RabbitMQ for any anomalous authentication patterns or unauthorized access attempts using newly disclosed credentials.
