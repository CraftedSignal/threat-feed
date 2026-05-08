---
title: free5GC SMF Unauthenticated UPI Access
slug: 2026-05-free5gc-smf-auth-bypass
description: free5GC's Session Management Function (SMF) UPI interface lacks authentication, allowing unauthenticated network attackers to read/write/delete UP-node and link topology data via exposed APIs.
date: "2026-05-09T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - 5G
  - Authentication Bypass
  - free5GC
  - SMF
  - UPI
  - CVE-2026-44329
vendors:
  - free5GC
products:
  - SMF
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-3258-qmv8-frp3
  - https://github.com/free5gc/free5gc/issues/887
  - https://github.com/free5gc/smf/pull/197
iocs:
  - type: url
    value: http://10.100.200.6:8000/upi/v1/upNodesLinks
  - type: url
    value: http://10.100.200.6:8000/nsmf-oam/v1/
ioc_counts:
  url: 2
rules:
  - title: Detect Unauthenticated SMF UPI Access
    description: Detects CVE-2026-44329 exploitation — HTTP requests to the /upi/v1/upNodesLinks endpoint without an Authorization header indicating a potential authentication bypass attempt
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SMF UPI POST Requests with Suspicious UPF Node Data
    description: Detects suspicious POST requests to the SMF UPI endpoint that could indicate an attempt to inject malicious UPF node data. Focuses on unusual IP addresses in the nodeID field.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

free5GC's Session Management Function (SMF) is vulnerable to an authentication bypass in its UPI (UP-node and link topology management) interface. The UPI route group is mounted without OAuth2/bearer-token authorization middleware, which allows any network attacker who can reach the SMF on the SBI interface to access UPI endpoints without providing any credentials. This vulnerability allows attackers to read the SMF's view of the UP-plane topology, inject attacker-controlled UPF nodes and links, and delete existing entries. The vulnerability affects free5GC SMF versions prior to 1.4.3 and was validated against the `free5gc/smf:v4.2.0` Docker image from the official Docker compose lab. The vulnerability was addressed in https://github.com/free5gc/smf/pull/197.

## Attack Chain

1. An attacker identifies the SMF instance on the SBI network at 10.100.200.6:8000.
2. The attacker sends an HTTP GET request to `/upi/v1/upNodesLinks` without an `Authorization` header to enumerate existing UPF nodes and links.
3. The SMF server responds with a `200 OK` status code and the current UP-node and link topology data.
4. The attacker crafts a malicious JSON payload containing attacker-controlled UPF node and link information.
5. The attacker sends an HTTP POST request to `/upi/v1/upNodesLinks` with the malicious JSON payload and without an `Authorization` header.
6. The SMF server processes the request and injects the attacker-controlled UPF node and link entries, returning a `200 OK` status code.
7. The attacker can then send a DELETE request to `/upi/v1/upNodesLinks/{nodeID}` to delete named UPF entries, even with a forged `Authorization` header.
8. The SMF server deletes the specified UPF entry, disrupting legitimate UPF participation in SMF's selection logic.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to fully compromise the integrity of the SMF's view of the UP-plane topology. This can lead to the injection of rogue UPF nodes, redirection of traffic through attacker-controlled infrastructure, and denial of service by deleting legitimate UPF entries. Given the core functionality of the SMF in a 5G network, this vulnerability could have a significant impact on network availability, security, and performance.

## Recommendation

*   Apply the patch available at https://github.com/free5gc/smf/pull/197 to upgrade to SMF version 1.4.3 or later to remediate CVE-2026-44329.
*   Monitor webserver logs for HTTP requests to the `/upi/v1/upNodesLinks` endpoint without an `Authorization` header using the "Detect Unauthenticated SMF UPI Access" Sigma rule.
*   Inspect network traffic for POST requests to `/upi/v1/upNodesLinks` containing suspicious or unexpected UPF node configurations.
*   Implement network segmentation to restrict access to the SMF SBI interface to only authorized and authenticated clients, mitigating the risk of unauthorized access.
