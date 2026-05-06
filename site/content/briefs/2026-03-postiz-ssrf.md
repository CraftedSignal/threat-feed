---
title: Postiz App SSRF Vulnerability via Next.js
slug: 2026-03-postiz-ssrf
description: A high-severity SSRF vulnerability exists in the Postiz application via Next.js, allowing attackers to bypass firewalls, scan internal networks, access sensitive cloud metadata (AWS IMDS), potentially leak instance credentials, and pivot within the internal network.
date: "2026-03-27T15:46:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-vj2p-7pgw-g2wf
rules:
  - title: Detect SSRF Attempt to AWS IMDS
    description: Detects attempts to exploit SSRF vulnerabilities to access the AWS Instance Metadata Service (IMDS) endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SSRF Attempt to AWS IMDS - POST
    description: Detects attempts to exploit SSRF vulnerabilities to access the AWS Instance Metadata Service (IMDS) endpoint using a POST request.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Postiz application, a web application built with Next.js, is vulnerable to Server-Side Request Forgery (SSRF). This vulnerability (CVE-2024-34351) allows an attacker to force the server to make HTTP requests to arbitrary domains. Exploitation can lead to internal network reconnaissance, access to sensitive cloud metadata, and potential credential theft. The vulnerability affects Postiz versions 2.0.12 and earlier. Users are advised to upgrade to version 2.21.1 to mitigate the risk. The primary concern is unauthorized access to internal resources and sensitive data through manipulated server-side requests.

## Attack Chain

1.  The attacker identifies a vulnerable endpoint in the Postiz application that accepts a URL as input.
2.  The attacker crafts a malicious URL pointing to an internal resource, such as `http://169.254.169.254/latest/meta-data/`.
3.  The Postiz server, without proper validation, makes an HTTP request to the specified URL.
4.  If successful, the server retrieves the requested data from the internal resource.
5.  The server returns the retrieved data to the attacker in the HTTP response.
6.  The attacker obtains sensitive information such as AWS instance metadata, including IAM roles and access keys.
7.  The attacker uses the compromised credentials to pivot into other AWS resources or the internal network.

## Impact

A successful SSRF attack can have significant consequences. Attackers can bypass firewall restrictions to scan and interact with internal network services, potentially discovering sensitive information and exploiting further vulnerabilities. Accessing cloud metadata services like AWS IMDS allows for the theft of instance credentials, enabling attackers to compromise other AWS resources and escalate their privileges. This vulnerability can lead to a full compromise of the internal network environment where Postiz is hosted, potentially impacting all services and data within that environment.

## Recommendation

*   Upgrade Postiz to version v2.21.1 to patch the SSRF vulnerability as recommended by the vendor.
*   Deploy the Sigma rule "Detect SSRF Attempt to AWS IMDS" to identify attempts to access the AWS metadata service (169.254.169.254) via HTTP requests.
*   Monitor web server logs for unusual outbound HTTP requests to internal IP addresses and private networks, specifically those originating from the Postiz application.
