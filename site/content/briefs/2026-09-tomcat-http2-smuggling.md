---
title: Apache Tomcat HTTP/2 Request Smuggling Vulnerability
slug: 2026-09-tomcat-http2-smuggling
description: A critical HTTP/2 request smuggling vulnerability, CVE-2026-86350, allows unauthenticated attackers to induce dynamic table desynchronization in Apache Tomcat via crafted header blocks.
date: "2026-09-26T01:35:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - webserver
  - request-smuggling
vendors:
  - Apache Software Foundation
products:
  - Apache Tomcat (<= 9.0.121, 10.1.55-10.1.59, 11.0.22-11.0.25)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A regression in the CVE-2026-41293 HTTP/2 header-validation refactor can mix request headers.
    confidence_band: high
cves:
  - id: CVE-2026-86350
    cvss: 9.1
    epss: 0.00313
  - id: CVE-2026-41293
    cvss: 9.8
    epss: 0.0168
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86350
  - https://tomcat.apache.org/security-9.html
  - https://github.com/apache/tomcat/commit/5adadc4ef413d5050f664d40800bbff74bd5d5ed
  - https://lists.apache.org/thread/mss45z99lcdd5dtpgcn45dy82f3toswc
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Apache Tomcat to 9.0.122, 10.1.60, or 11.0.26
      owner: IT Operations
      due: 24h
      evidence: Vendor remediation guidance
  hunt_leads:
    - lead: Search logs for IllegalArgumentException in org.apache.coyote.http2
      technique_id: T1190
      data_needed:
        - Application logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability requires invalid field input that throws an exception
  mitigation_plan:
    - priority: immediate
      action: Disable HTTP/2 support
      owner: IT Operations
      addresses: CVE-2026-86350
      evidence: Disabling the vulnerable protocol mitigates the risk
---

CVE-2026-86350 is a critical HTTP/2 request smuggling vulnerability affecting Apache Tomcat versions through 9.0.121, 10.1.55-10.1.59, and 11.0.22-11.0.25. The flaw originates from a regression in the HPACK header validation logic introduced during the refactor for CVE-2026-41293. When an attacker sends a specially crafted HTTP/2 request containing an invalid HPACK field, the decoder throws an exception and halts processing, preventing subsequent fields in that request from being added to the HPACK dynamic table. 

Because the dynamic table state becomes desynchronized, subsequent HTTP/2 requests multiplexed over the same TCP connection will index headers against an incorrect or stale table state. This allows for header mixing or request smuggling, where an attacker can influence the interpretation of later requests. This vulnerability is rated with a CVSS score of 9.1 and represents a significant risk for environments relying on HTTP/2 multiplexing. The vulnerability does not provide direct remote code execution, but facilitates security bypasses by poisoning the request context.

## Attack Chain

1. Attacker establishes a standard HTTP/2 connection with the target Apache Tomcat server via a preface.
2. Attacker initiates an HTTP/2 stream (Stream 1) and submits a HEADERS frame containing a malformed or invalid field value.
3. The `HpackDecoder` processes the stream and encounters the invalid field, triggering an `IllegalArgumentException`.
4. The decoder terminates the processing of Stream 1, intentionally failing to update the HPACK dynamic table with subsequent valid headers.
5. The server keeps the TCP connection open, maintaining the desynchronized dynamic table state.
6. Attacker initiates a second HTTP/2 stream (Stream 2) on the same connection, using indices that rely on the expected state of the dynamic table.
7. The Tomcat server processes Stream 2 using the corrupted table state, causing the server to misinterpret the attacker's headers.
8. The final objective is achieved when the smuggled request is processed with the attacker's injected header context, potentially bypassing access controls or application logic.

## Impact

Successful exploitation allows an unauthenticated attacker to smuggle requests, potentially bypassing security controls, gaining unauthorized access to sensitive application paths, or manipulating request routing. While not a direct RCE, the ability to desynchronize request headers allows for complex application-layer attacks. The vulnerability affects a wide range of Tomcat deployments globally where HTTP/2 is enabled.

## Recommendation

1. Upgrade all instances of Apache Tomcat to 9.0.122, 10.1.60, 11.0.26, or newer immediately to patch the HPACK validation regression.
2. If an immediate upgrade is not possible, disable HTTP/2 support in the Tomcat configuration until patching is complete.
3. Ensure the 'examples' web application is removed from production environments to reduce the surface area for testing and exploitation.
4. Hunt for anomalous HTTP/2 traffic patterns or logs indicating frequent `IllegalArgumentException` events originating from the `org.apache.coyote.http2` package in server logs.
