---
title: NATS Server Authorization Bypass Vulnerability (CVE-2026-58252)
slug: 2026-07-nats-server-authz-bypass
description: CVE-2026-58252 identifies an authorization bypass vulnerability in NATS Server, described as a 'Subscribe Authz Bypass via Wildcard-Overlap', which allows unauthorized access or actions by exploiting how wildcard subscriptions are handled.
date: "2026-07-11T07:37:18Z"
lastmod: "2026-07-11T07:38:25Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - authorization-bypass
  - cve
  - nats
  - server
  - vulnerability
  - mqtt
  - information-disclosure
  - filter-bypass
vendors:
  - NATS
products:
  - NATS Server
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A vulnerability, CVE-2026-58209, exists in NATS Server related to its MQTT functionality. This flaw allows an attacker to bypass subscribe deny filters when using MQTT retained messages and Quality of Service (QoS) replay, potentially leading to unauthorized access to messages.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1568
    technique_name: Application Data from Cloud Storage
    evidence: potentially leading to unauthorized access to messages.
    confidence_band: med
cves:
  - id: CVE-2026-58252
    cvss: 6.5
    epss: 0.00465
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58252
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58209
updates:
  - at: "2026-07-11T07:38:25Z"
    level: L1
    summary: 'merged source coverage: NATS Server MQTT Vulnerability Allows Subscribe Deny Filter Bypass (CVE-2026-58209)'
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58209
---

Information published by the Microsoft Security Response Center (MSRC) on July 11, 2026, details CVE-2026-58252, an authorization bypass vulnerability affecting NATS Server. This critical flaw, labeled as a "Subscribe Authz Bypass via Wildcard-Overlap," allows an attacker to circumvent established security controls by exploiting how the server processes wildcard subscriptions. Specifically, a malicious actor could craft a subscription request that, due to an oversight in the wildcard matching logic, grants them unauthorized access to message streams they should not be privileged to view. This vulnerability could enable attackers to intercept sensitive data or gain insights into system operations, depending on the information transmitted over the NATS network. No specific campaigns or evidence of active exploitation are provided in the available MSRC bulletin.

## Attack Chain

The provided intelligence details a vulnerability (CVE-2026-58252) but does not include specific steps for its exploitation. An attacker would likely need authenticated access, albeit with limited privileges, to the NATS Server to leverage the "Subscribe Authz Bypass via Wildcard-Overlap". They would then craft a special wildcard subscription pattern designed to bypass the server's authorization checks. Upon successful exploitation, the NATS Server would mistakenly grant the attacker access to message topics or streams that their legitimate privileges would otherwise deny. The final objective would be unauthorized data access or information disclosure. Without more specific details from the vendor, further steps of a real-world attack chain cannot be accurately described.

## Impact

A successful exploitation of CVE-2026-58252 would primarily lead to unauthorized information disclosure and potential data breaches within environments utilizing NATS Server. An attacker leveraging this authorization bypass could gain access to sensitive messages and data streams flowing through the NATS infrastructure, potentially exposing confidential business information, user data, or system operational details. While the source does not provide specific victim counts or targeted sectors, any organization using vulnerable versions of NATS Server is at risk of its internal communications being compromised. The full extent of impact depends on the criticality and sensitivity of the data being transmitted via the NATS messaging system.

## Recommendation

* Immediately patch all NATS Server instances to a version that addresses CVE-2026-58252, as detailed in the Microsoft Security Response Center advisory.
* Review NATS Server configuration for authorization policies, ensuring strict least-privilege principles are applied to all users and services.
* Monitor NATS Server logs for unusual subscription patterns or attempts by low-privileged users to access sensitive topics.
