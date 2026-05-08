---
title: free5GC NEF PATCH Handler Vulnerability Leads to Denial of Service
slug: 2026-05-free5gc-nef-panic
description: A nil pointer dereference vulnerability exists in free5GC's NEF PATCH /3gpp-pfd-management/v1/{afId}/transactions/{transId}/applications/{appId} handler when UDR access fails, causing a denial-of-service condition.
date: "2026-05-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - free5GC
  - NEF
  - CVE-2026-44322
vendors:
  - free5GC
products:
  - nef 4.2.1
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Availability
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-j59f-x285-69jx
  - https://github.com/free5gc/free5gc/issues/925
  - https://github.com/free5gc/nef/pull/22
iocs:
  - type: url
    value: http://10.100.200.19:8000/3gpp-traffic-influence/v1/afnpd3/subscriptions
  - type: url
    value: http://10.100.200.19:8000/3gpp-pfd-management/v1/afnpd3/transactions
  - type: url
    value: http://10.100.200.19:8000/3gpp-pfd-management/v1/afnpd3/transactions/1/applications/appnpd3
ioc_counts:
  url: 3
rules:
  - title: Detect CVE-2026-44322 Exploitation — NEF PATCH Endpoint HTTP 500 Error
    description: Detects CVE-2026-44322 exploitation — HTTP 500 errors returned by the NEF PATCH endpoint, indicating a potential denial-of-service condition.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
  - title: Detect NEF Panic Logs Related to PFD Management
    description: Detects panic logs in NEF related to the PatchIndividualApplicationPFDManagement function, indicating a potential nil pointer dereference.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A vulnerability exists in free5GC's NEF (Network Exposure Function) component, specifically in the `PATCH /3gpp-pfd-management/v1/{afId}/transactions/{transId}/applications/{appId}` handler. This vulnerability, present in version 4.2.1, stems from a nil pointer dereference that occurs when the upstream UDR (User Data Repository) call fails and the consumer wrapper returns an error along with a nil `*ProblemDetails`. The handler incorrectly attempts to access the `Cause` field of a nil `problemDetails` object, leading to a panic. While Gin recovery converts this panic into an HTTP 500 error, it effectively results in a denial-of-service condition for a single PATCH request. The issue is triggered when UDR access is failing, for example because the NRF or UDR is unreachable or broken. This vulnerability is reachable without authentication.

## Attack Chain

1. An attacker sends a POST request to create an AF context using the `/3gpp-traffic-influence/v1/afnpd3/subscriptions` endpoint, without any Authorization header.
2. The attacker then sends a POST request to create a PFD-management transaction using the `/3gpp-pfd-management/v1/afnpd3/transactions` endpoint, including PFD data in the request body.
3. The attacker causes UDR access to fail, simulating this by stopping the NRF (Network Repository Function) service. This leads to NEF's UDR client being unable to discover or dial the UDR.
4. The attacker sends a PATCH request to `/3gpp-pfd-management/v1/afnpd3/transactions/1/applications/appnpd3`, triggering the vulnerable code path.
5. The NEF attempts to process the PATCH request but fails to access the UDR due to the NRF outage.
6. The `PatchIndividualApplicationPFDManagement` function encounters an error because `problemDetails` is nil, causing a nil pointer dereference at `NFs/nef/internal/sbi/processor/pfd.go:622`.
7. Gin recovery catches the panic, converting it into an HTTP 500 Internal Server Error.
8. The attacker receives an HTTP 500 response, indicating the denial-of-service condition.

## Impact

The vulnerability results in a NULL pointer dereference (CWE-476), leading to a denial-of-service condition. Although Gin recovery prevents the NEF process from crashing entirely, a successful attack causes the affected PATCH endpoint to return HTTP 500 errors instead of the intended controlled error response. The attacker does not directly control the prerequisite condition of UDR access failure. The vulnerability affects free5GC version 4.2.1.

## Recommendation

*   Apply the upstream fix available in the NEF repository (https://github.com/free5gc/nef/pull/22) to resolve the nil pointer dereference.
*   Monitor NEF logs for panic errors originating from `NFs/nef/internal/sbi/processor/pfd.go:622` to detect potential exploitation attempts.
*   Deploy the Sigma rule to detect HTTP 500 errors from the vulnerable endpoint, indicative of the denial-of-service condition.
