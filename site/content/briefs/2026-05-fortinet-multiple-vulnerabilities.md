---
title: Fortinet Patches Multiple Vulnerabilities in FortiAuthenticator, FortiOS, and FortiSandbox
slug: 2026-05-fortinet-multiple-vulnerabilities
description: Fortinet released security advisories on May 12, 2026, addressing critical vulnerabilities including improper access control, incorrect global authorization, and out-of-bounds access across FortiAuthenticator, FortiOS, and FortiSandbox product lines, urging users to apply necessary updates.
date: "2026-05-12T19:05:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - fortinet
  - vulnerability
  - patch
vendors:
  - Fortinet
products:
  - FortiAuthenticator (8.0.2)
  - FortiAuthenticator (8.0.0)
  - FortiAuthenticator (6.6.0 to 6.6.8)
  - FortiAuthenticator (6.5.0 to 6.5.6)
  - FortiOS (7.6.0 to 7.6.3)
  - FortiOS (7.4.0 to 7.4.8)
  - FortiOS (7.2.0 to 7.2.11)
  - FortiSandbox (5.0.0 to 5.0.1)
  - FortiSandbox (4.4.0 to 4.4.8)
  - FortiSandbox Cloud 24
  - FortiSandbox Cloud 23
  - FortiSandbox Cloud 5.0 (5.0.2 to 5.0.5)
  - FortiSandbox PaaS 23.4
  - FortiSandbox PaaS 23.3
  - FortiSandbox PaaS 23.1
  - FortiSandbox PaaS 22.2
  - FortiSandbox PaaS 22.1
  - FortiSandbox PaaS 21.4
  - FortiSandbox PaaS 21.3
  - FortiSandbox PaaS 5.0 (5.0.0 to 5.0.1)
  - FortiSandbox PaaS 4.4 (4.4.5 to 4.4.8)
references:
  - https://cyber.gc.ca/en/alerts-advisories/fortinet-security-advisory-av26-454
  - https://www.fortiguard.com/psirt/FG-IR-26-128
  - https://www.fortiguard.com/psirt/FG-IR-26-136
  - https://www.fortiguard.com/psirt/FG-IR-26-123
  - https://www.fortiguard.com/psirt?filter=1&version=&severity=5&severity=4&severity=3&severity=2
rules:
  - title: Detect Unauthorized Access to Fortinet API Endpoints
    description: Detects potential unauthorized access attempts to Fortinet API endpoints, potentially exploiting FG-IR-26-128.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Out-of-Bounds Access in CAPWAP Daemon
    description: Detects potential exploitation of out-of-bounds access in the CAPWAP daemon, potentially related to FG-IR-26-123.
    platform: sigma
    severity: low
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - network_connection
rules_count: 2
---

On May 12, 2026, Fortinet issued multiple security advisories addressing vulnerabilities found within its FortiAuthenticator, FortiOS, and FortiSandbox product lines. These advisories detail critical vulnerabilities such as improper access control on API endpoints, incorrect global authorization, and out-of-bounds memory access, potentially leading to unauthorized access or denial-of-service conditions. The affected products and versions include a range of releases, including FortiAuthenticator (versions 6.5.0 to 8.0.2), FortiOS (versions 7.2.0 to 7.6.3), and FortiSandbox (versions 4.4.0 to Cloud 24). Defenders should promptly review the advisories and apply the provided updates to mitigate potential risks.

## Attack Chain

Given the nature of the vulnerabilities (improper access control, incorrect authorization, and out-of-bounds access), the following represents a generalized attack chain:

1.  **Reconnaissance:** Attacker identifies a vulnerable Fortinet appliance exposed to the network.
2.  **Initial Access:** Exploiting an improper access control vulnerability (FG-IR-26-128) to gain unauthorized access to API endpoints.
3.  **Privilege Escalation:** Leveraging an incorrect global authorization vulnerability (FG-IR-26-136) to escalate privileges within the system.
4.  **Lateral Movement (Conditional):** Depending on the configuration and network segmentation, the attacker may be able to use their elevated privileges to move laterally within the network.
5.  **Out-of-bounds Access:** Triggering an out-of-bounds memory access in the CAPWAP daemon (FG-IR-26-123), potentially leading to denial of service or information disclosure.
6.  **Data Exfiltration or System Compromise:** Using the compromised system to exfiltrate sensitive data or further compromise other systems on the network.

## Impact

Successful exploitation of these vulnerabilities could allow attackers to gain unauthorized access to sensitive data, escalate privileges within the network, or cause denial-of-service conditions. The widespread use of Fortinet products across various sectors means a successful attack could impact numerous organizations.

## Recommendation

*   Immediately apply the updates provided in the Fortinet security advisories ([https://www.fortiguard.com/psirt](https://www.fortiguard.com/psirt?filter=1&version=&severity=5&severity=4&severity=3&severity=2)) to address the vulnerabilities in FortiAuthenticator, FortiOS, and FortiSandbox.
*   Monitor network traffic for unusual activity related to Fortinet appliances, and deploy the Sigma rule below to detect unauthorized access attempts to API endpoints.
*   Review access control policies and authentication mechanisms on Fortinet appliances to ensure proper security configurations.
