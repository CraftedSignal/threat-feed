---
title: free5gc UDR Improper Path Validation Allows Unauthenticated Access to Traffic Influence Subscriptions
slug: 2026-04-free5gc-udr-path-validation
description: An improper path validation vulnerability exists in the free5gc UDR service, allowing unauthenticated attackers with access to the 5G Service Based Interface (SBI) to read Traffic Influence Subscriptions.
date: "2026-04-14T20:01:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - free5GC
  - UDR
  - path-validation
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-x5r2-r74c-3w28
iocs:
  - type: url
    value: http://evil.com/notify
ioc_counts:
  url: 1
rules:
  - title: Detect free5GC UDR Path Traversal Attempt
    description: Detects attempts to exploit the free5GC UDR path traversal vulnerability by monitoring for 404 responses with JSON content in the response body.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect free5GC UDR Subscription Creation with Suspicious Notification URI
    description: Detects attempts to create Traffic Influence Subscriptions with a suspicious notification URI.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

An improper path validation vulnerability in the free5gc UDR (User Data Repository) service allows unauthenticated attackers with network access to the 5G Service Based Interface (SBI) to read Traffic Influence Subscriptions. The vulnerability, present in versions up to 1.4.2, stems from a missing `return` statement after an HTTP 404 response is sent for an invalid path. This allows the request to continue processing and return subscription data despite the invalid path. An attacker can exploit this by providing an arbitrary value instead of the expected `subs-to-notify` path segment in a GET request. Successful exploitation allows the attacker to retrieve sensitive subscriber-related information, impacting deployments where the SBI is reachable by untrusted parties.

## Attack Chain

1.  Attacker identifies a vulnerable free5GC UDR instance with a reachable SBI.
2.  Attacker creates a Traffic Influence Subscription using a POST request to `/nudr-dr/v2/application-data/influenceData/subs-to-notify` to obtain a valid `subscriptionId`.
3.  The UDR service creates and stores the subscription, assigning a unique `subscriptionId`.
4.  Attacker crafts a GET request to `/nudr-dr/v2/application-data/influenceData/{influenceId}/{subscriptionId}` with an invalid `influenceId` (e.g., "WRONGID") but the valid `subscriptionId` obtained in step 2.
5.  The UDR service's `HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdGet` function checks if `influenceId` is not equal to "subs-to-notify".
6.  The function incorrectly sends a "404 page not found" response but fails to terminate the request processing.
7.  The request processing continues, retrieving the subscription data associated with the valid `subscriptionId`.
8.  The UDR service returns the 404 error message along with the subscription object (containing sensitive information) in the same HTTP response body, disclosing subscriber data.

## Impact

This vulnerability allows unauthenticated attackers to retrieve Traffic Influence Subscription objects without proper authorization. Successful exploitation results in the disclosure of sensitive subscriber-related information, including SUPIs/IMSIs, DNNs, S-NSSAIs, and callback notification URI values. This data can be used for further malicious activities such as subscriber tracking or unauthorized service access. Any free5GC deployment with a reachable SBI is potentially impacted. The severity is high due to the ease of exploitation and the sensitivity of the disclosed information.

## Recommendation

*   Apply the patch provided by free5GC, which adds the missing `return` statement in `NFs/udr/internal/sbi/api_datarepository.go` to prevent further processing after sending the 404 response.
*   Monitor webserver logs for GET requests to `/nudr-dr/v2/application-data/influenceData/*` that return a 404 status code along with a JSON body to detect potential exploitation attempts. Implement a detection rule similar to the "Detect free5GC UDR Path Traversal Attempt" Sigma rule provided below.
*   Block the callback notification URI `http://evil.com/notify` listed in the IOC table at the network or application firewall to prevent potential callback exploitation.
*   Upgrade the `go/github.com/free5gc/udr` package to a version greater than 1.4.2 to remediate CVE-2026-40247.
