---
title: AWS Smithy-RS HTTP Server Vulnerable to Unauthenticated Slowloris Denial of Service
slug: 2026-07-aws-smithy-http-server-dos
description: An unauthenticated Slowloris denial of service vulnerability exists in the default `serve()` path of AWS's `aws-smithy-http-server` framework (versions <= 0.66.4), allowing remote attackers to exhaust server resources by initiating numerous incomplete connections.
date: "2026-07-24T22:45:26Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - webserver
  - rust
  - aws
vendors:
  - AWS
products:
  - aws-smithy-http-server (<= 0.66.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: allocation of resources without limits in the default aws-smithy-http-server serve() path allows unauthenticated Slowloris denial of service
    confidence_band: high
cves:
  - id: CVE-2026-16756
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-jvxp-qmx7-gjpx
---

A critical vulnerability (CVE-2026-16756) has been identified in the `aws-smithy-http-server` component of Smithy-RS, a Rust framework for generating HTTP clients and servers used in the AWS SDK for Rust and custom service implementations. This flaw affects versions 0.66.4 and earlier. The vulnerability stems from the server's default `serve()` path lacking connection and header-read timeouts, as well as a concurrent-connection cap. This omission allows an unauthenticated remote attacker to initiate a Slowloris-type denial of service attack by opening a large number of HTTP connections and sending partial, incomplete requests. These lingering connections consume server resources, ultimately exhausting available sockets and tasks, preventing legitimate users from accessing the service. AWS recommends immediate upgrade to patched versions.

## Attack Chain

1. An unauthenticated remote attacker identifies a target server running an affected `aws-smithy-http-server` instance.
2. The attacker initiates a large number of concurrent TCP connections to the target server's HTTP port.
3. For each established connection, the attacker sends only a partial HTTP request header, for example, just the "GET / HTTP/1.1" line without the subsequent newlines or additional headers.
4. The attacker periodically sends a small amount of junk data (e.g., an arbitrary HTTP header line followed by a partial newline) over each partial connection to prevent the server from timing out the connection due to inactivity.
5. The `aws-smithy-http-server`, due to its lack of connection timeouts and concurrent-connection limits, keeps these numerous partial connections open and allocates resources for them.
6. As the attacker continues this process, the server's pool of available sockets and task processing capacity becomes exhausted, leading to resource starvation.
7. Legitimate clients attempting to connect to the server are unable to establish new connections or receive responses, resulting in a denial of service for all users.
8. The attack continues as long as the attacker maintains the partial connections, effectively rendering the service unavailable.

## Impact

Successful exploitation of CVE-2026-16756 can lead to a complete denial of service for affected `aws-smithy-http-server` instances. Attackers can render applications and services built with Smithy-RS, including custom service implementations and potentially components of the AWS SDK for Rust, unreachable. The server's sockets and processing tasks will be exhausted by the malicious partial connections, preventing legitimate users from accessing the service. This can lead to significant operational disruptions, loss of revenue, and damage to reputation for organizations relying on these services. The vulnerability is unauthenticated, meaning any remote attacker can initiate the attack without prior access or credentials.

## Recommendation

* Patch CVE-2026-16756 immediately by upgrading `aws-smithy-http-server` to version 0.66.5 or later.
* Monitor network connection logs and application performance metrics for an abnormally high number of concurrent, long-lived, or incomplete connections to services utilizing `aws-smithy-http-server`.
* Implement network-level rate limiting or connection throttling on ingress points to protect services from large-scale connection floods.
* Deploy intrusion prevention systems (IPS) or Web Application Firewalls (WAFs) capable of detecting and mitigating Slowloris-type denial of service attacks.
