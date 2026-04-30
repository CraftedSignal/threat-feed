---
title: Flowise SSRF Protection Bypass via Unprotected Built-in HTTP Modules
slug: 2024-01-09-flowise-ssrf
description: Flowise is vulnerable to SSRF protection bypass via unprotected built-in HTTP modules in the custom function sandbox, allowing authenticated users to access internal network resources by exploiting the lack of SSRF protection on Node.js `http`, `https`, and `net` modules.
date: "2026-04-16T21:50:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - flowise
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-xhmj-rg95-44hv
rules:
  - title: Flowise SSRF Using HTTP Module
    description: Detects SSRF attempts in Flowise by monitoring for HTTP requests originating from the custom function feature that target cloud metadata endpoints using the built-in http module.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Flowise Custom Function Execution with Network Activity
    description: Detects the execution of custom functions in Flowise that results in network connections, which may indicate SSRF attempts or other malicious activities.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Flowise, a low-code platform for building custom automation workflows, is susceptible to a Server-Side Request Forgery (SSRF) protection bypass. This vulnerability stems from the application's incomplete implementation of SSRF defenses. While `axios` and `node-fetch` libraries are secured with an `HTTP_DENY_LIST`, the built-in Node.js modules `http`, `https`, and `net` are permitted within the NodeVM sandbox without any equivalent restrictions. An authenticated attacker can exploit this oversight in Flowise version 3.0.13 and earlier to make arbitrary HTTP requests to internal network resources. This issue allows bypassing intended security controls and potentially accessing sensitive information, such as cloud provider metadata services.

## Attack Chain

1.  The attacker authenticates to a Flowise instance using a valid API key or session.
2.  The attacker crafts a malicious JavaScript payload designed to exploit the custom function feature.
3.  The malicious payload imports the built-in `http` module.
4.  The payload constructs an HTTP request targeting an internal resource, such as the AWS metadata service at `169.254.169.254`.
5.  The request includes a header to obtain an IAM token: `'X-aws-ec2-metadata-token-ttl-seconds': '21600'`.
6.  The payload uses the obtained IAM token to request temporary AWS credentials from the metadata service.
7.  The custom function executes the code within the NodeVM sandbox, bypassing the intended SSRF protection.
8.  The attacker retrieves the temporary AWS credentials from the metadata service, potentially leading to unauthorized access to AWS resources.

## Impact

Successful exploitation of this SSRF vulnerability can have significant consequences. Attackers can steal temporary IAM credentials from cloud provider metadata services, granting them unauthorized access to other cloud resources. Furthermore, they can scan internal networks to discover services and identify additional attack targets. The ability to reach databases, admin panels, and other internal APIs that should not be externally accessible poses a severe security risk, potentially leading to data breaches or system compromise. All Flowise deployments where `HTTP_DENY_LIST` is configured for SSRF protection are vulnerable, while deployments without it are already generally vulnerable to SSRF.

## Recommendation

*   Apply the necessary patches to Flowise to remediate the SSRF vulnerability as described in GHSA-xhmj-rg95-44hv.
*   Deploy the following Sigma rule to detect exploitation attempts involving the `http` module targeting common cloud metadata endpoints: `Flowise SSRF Using HTTP Module`.
*   Enable logging of HTTP requests originating from the Flowise server to aid in identifying and investigating potential SSRF attacks.
*   Review and harden network segmentation to limit the impact of potential SSRF vulnerabilities.
*   Consider disabling the custom function feature if it is not essential to the functionality of the Flowise deployment.
