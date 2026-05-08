---
title: free5GC NRF Type Confusion Vulnerability in /oauth2/token Endpoint
slug: 2026-05-free5gc-nrf-type-confusion
description: The free5GC NRF's /oauth2/token endpoint is vulnerable to a type confusion vulnerability due to incorrect parsing of form data, leading to a denial-of-service via unauthenticated requests.
date: "2026-05-09T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - type-confusion
  - denial-of-service
  - free5GC
vendors:
  - free5GC
products:
  - nrf:v4.2.1
  - go/github.com/free5gc/nrf (< 1.4.3)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-f8qv-7x5w-qr48
  - https://github.com/free5gc/free5gc/issues/918
  - https://github.com/free5gc/nrf/pull/83
iocs:
  - type: url
    value: http://10.100.200.3:8000/oauth2/token
ioc_counts:
  url: 1
rules:
  - title: Detect free5GC NRF Type Confusion Attempt
    description: Detects CVE-2026-44325 exploitation attempt — HTTP POST to /oauth2/token with vulnerable parameters
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - webserver
  - title: Detect free5GC NRF Type Confusion Panic in Logs
    description: Detects CVE-2026-44325 exploitation — PANIC log message indicating a type confusion during request handling in free5GC NRF
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - webserver
rules_count: 2
---

A type confusion vulnerability exists in the free5GC NRF (Network Repository Function) version 4.2.1, specifically within the `/oauth2/token` endpoint. This endpoint, which is intentionally unauthenticated as it is the OAuth2 token issuance endpoint, is susceptible to a parser-level bug. The vulnerability lies in how the `NFs/nrf/internal/sbi/api_accesstoken.go` handler processes incoming form data. The handler uses reflection on the `models.NrfAccessTokenAccessTokenReq` struct, but incorrectly treats most fields as `models.PlmnId` types. This leads to a panic when the parsed value is assigned to a field with an incompatible type, such as slices or different struct pointers. Although the Gin recovery mechanism catches the panic, converting it to an HTTP 500 error, the endpoint remains vulnerable to repeated denial-of-service attacks via single, unauthenticated form-encoded POST requests. This issue affects free5GC version 4.2.1.

## Attack Chain

1.  Attacker sends an HTTP POST request to the `/oauth2/token` endpoint of the free5GC NRF at `http://10.100.200.3:8000`.
2.  The request includes a `Content-Type` header set to `application/x-www-form-urlencoded`.
3.  The request body contains a URL-encoded parameter, such as `requesterPlmnList`, `requesterSnssaiList`, `requesterSnpnList`, `targetSnpn`, `targetSnssaiList`, or `targetNsiList`, with a value intended to trigger the type confusion. For example: `requesterPlmnList={"mcc":"208","mnc":"93"}`.
4.  The NRF's `api_accesstoken.go` handler parses the form data and reflects over the `models.NrfAccessTokenAccessTokenReq` struct.
5.  Due to incorrect type handling, the handler attempts to assign a value of type `*models.PlmnId` to a field of an incompatible type (e.g., `[]models.PlmnId` for the `requesterPlmnList` field).
6.  The `reflect.Set` operation panics due to the type mismatch.
7.  The Gin recovery middleware catches the panic and converts it into an HTTP 500 Internal Server Error.
8.  The NRF process continues to run, but the specific request is not processed successfully, and an error message is logged.

## Impact

The type confusion vulnerability (CWE-843) in the `/oauth2/token` endpoint allows an attacker to cause a denial-of-service (DoS) condition by sending crafted requests. Although the Gin recovery mechanism prevents the NRF process from crashing entirely, each malicious request consumes resources (CPU, log writes due to stack trace generation) and degrades the performance of the token issuance service. An attacker can repeatedly send these requests, potentially impacting legitimate clients and overwhelming the logs. The vulnerability affects free5GC version 4.2.1. There are at least 6 crashing fields which all crash due to the same root cause.

## Recommendation

*   Monitor webserver logs for HTTP POST requests to the `/oauth2/token` endpoint (IOC: `http://10.100.200.3:8000/oauth2/token`) containing parameters known to trigger the vulnerability (e.g., `requesterPlmnList`, `requesterSnssaiList`, `targetSnpn`) and deploy the "Detect free5GC NRF Type Confusion Attempt" Sigma rule.
*   Apply the upstream patch available at `https://github.com/free5gc/nrf/pull/83` to address the vulnerability.
*   Upgrade the go/github.com/free5gc/nrf package to a version greater than or equal to 1.4.3 to remediate CVE-2026-44325.
*   Implement input validation on the `/oauth2/token` endpoint to ensure that the types of the request parameters match the expected types in the `models.NrfAccessTokenAccessTokenReq` struct.
